#!/bin/bash

# list of vars to check
env_vars=(
    "WEB_APP_URL"
    "KEYCLOAK_ADMIN"
    "KEYCLOAK_ADMIN_PASSWORD"
    "KEYCLOAK_URL"
    "KEYCLOAK_REALM"
    "KEYCLOAK_CLIENT_ID"
    "KEYCLOAK_CLIENT_TYPE"
    "USER_FIRST_NAME"
    "USER_LAST_NAME"
    "USER_EMAIL"
    "USER_USERNAME"
    "USER_PASSWORD"
    "CREATE_CUSTOM_MAPPERS"
)

# Check vars are populated
echo "##### Checking config.env:"
for var in "${env_vars[@]}"; do
  if [ -n "${!var}" ]; then
    echo "=> '$var' is set to '${!var}'"
  else
    echo "##### ERROR: $var is empty, exiting.."
    exit 1
  fi
done

KEYCLOAK_CLIENT_SCOPE_NAME="$KEYCLOAK_CLIENT_ID-dedicated"

# Get an admin-scoped access token
get_access_token() {
  ACCESS_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$KEYCLOAK_ADMIN" \
    -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
    -d 'grant_type=password' \
    -d 'client_id=admin-cli' | jq -r '.access_token')
  echo $ACCESS_TOKEN
}

# Create realm
create_realm() {
  curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
      -H "Authorization: Bearer $NEW_TOKEN" \
      -H "Content-Type: application/json" \
      --data-raw "{
      \"realm\": \"$KEYCLOAK_REALM\",
      \"enabled\": true}"
  echo "##### realm '$KEYCLOAK_REALM' created"
}

# Create users
create_user() {
users=$(cat /config/users.json)
echo "Amount of users: $(echo "$users" | jq '. | length')"
echo "$users" | jq -c '.[]' | while read -r user; do
  firstName=$(echo "$user" | jq -r '.firstName')
  lastName=$(echo "$user" | jq -r '.lastName')
  username=$(echo "$user" | jq -r '.username')
  email=$(echo "$user" | jq -r '.email')
  password=$(echo "$user" | jq -r '.password')
  echo "##### creating user '$email' ..."
  curl -s -X POST "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/users" \
  -H "Authorization: Bearer $NEW_TOKEN" \
  -H "Content-Type: application/json" --data-raw "{
      \"firstName\":\"$firstName\",
      \"lastName\":\"$lastName\",
      \"email\":\"$email\",
      \"username\":\"$username\",
      \"enabled\":\"true\",
      \"emailVerified\": true,
      \"credentials\": [{\"type\": \"password\", \"value\": \"$password\", \"temporary\": false}]}"
  echo "##### user '$email' created"
done
}

# Create group
curl --location -s -X POST "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/groups" \
  -H 'accept: application/json, text/plain, */*' \
  -H "authorization: Bearer $TOKEN" \
  --data-raw "{\"name\":\"$GROUP_NAME\"}"

# add members to group
curl --location -s -X PUT "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/users/$USER_UUID/groups/$GROUP_UUID' \
  -H 'accept: application/json, text/plain, */*' \
  -H 'authorization: Bearer $TOKEN' \
  --data-raw '{}'"

# create groups mapper for client
curl --location -s -X POST "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID/protocol-mappers/models' \
  -H 'accept: application/json, text/plain, */*' \
  -H "authorization: Bearer $TOKEN" \
  --data-raw '{
    "protocol": "saml",
    "protocolMapper": "saml-group-membership-mapper",
    "name": "Groups Mapper",
    "config": {
        "attribute.name": "GROUPS",
        "friendly.name": "",
        "attribute.nameformat": "Basic",
        "single": "true",
        "full.path": "false"
    }
}'"

# Create an OIDC client
create_oidc_client() {
  echo "##### Creating OIDC client '$KEYCLOAK_CLIENT_ID'..."
  curl --location -s -X POST "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients" \
  --header "Authorization: Bearer $NEW_TOKEN" \
  --header 'Content-Type: application/json' \
  --data-raw "{
      \"clientId\": \"$KEYCLOAK_CLIENT_ID\",
      \"redirectUris\": [\"$WEB_APP_URL/auth/realms/runai/broker/oidc/endpoint\"],
      \"webOrigins\": [\"$WEB_APP_URL/*\"],
      \"attributes\": {
        \"login_theme\": \"genny\",
        \"post.logout.redirect.uris\": \"$WEB_APP_URL/*\"},
      \"standardFlowEnabled\": true
  }"
  echo "##### OIDC client '$KEYCLOAK_CLIENT_ID' created"
  CLIENT_UUID=$(curl --location -s -X GET "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients" \
  --header "Authorization: Bearer $NEW_TOKEN" \
  | jq -r ".[] | select(.clientId==\"$KEYCLOAK_CLIENT_ID\") | .id")
  echo "=> OIDC client UUID: '$CLIENT_UUID'"
  CLIENT_SECRET=$(curl --location -s -X GET "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID/client-secret" \
  --header "Authorization: Bearer $NEW_TOKEN" \
  | jq -r ".value")
  echo "##### client credentials retrieved"
  echo "=> OIDC client secret: '$CLIENT_SECRET'"
}

# Create a SAML client
create_saml_client() {
  echo "##### Creating SAML client '$KEYCLOAK_CLIENT_ID'..."
  curl --location -s -X POST "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients" \
  --header "Authorization: Bearer $TOKEN" \
  --header "Content-Type: application/json" \
  --data-raw "{
    \"protocol\": \"saml\",
    \"clientId\": \"$KEYCLOAK_CLIENT_ID\",
    \"name\": \"my test SAML client\",
    \"description\": \"\",
    \"publicClient\": true,
    \"authorizationServicesEnabled\": false,
    \"serviceAccountsEnabled\": false,
    \"implicitFlowEnabled\": false,
    \"directAccessGrantsEnabled\": true,
    \"standardFlowEnabled\": true,
    \"frontchannelLogout\": true,
    \"alwaysDisplayInConsole\": false,
    \"rootUrl\": \"$WEB_APP_URL\",
    \"baseUrl\": \"$WEB_APP_URL\",
    \"adminUrl\": \"\",
    \"redirectUris\": [\"$WEB_APP_URL/auth/realms/runai/broker/saml/endpoint\"],
    \"attributes\": {
        \"login_theme\": \"genny\",
        \"saml_force_name_id_format\": \"true\",
        \"saml.client.signature\": \"false\",
        \"saml_name_id_format\": \"email\",
        \"saml_idp_initiated_sso_url_name\": \"\",
        \"saml_idp_initiated_sso_relay_state\": \"\",
        \"post.logout.redirect.uris\": \"$WEB_APP_URL/*\"
    }
}"
  echo "##### SAML client '$KEYCLOAK_CLIENT_ID' created"
  CLIENT_UUID=$(curl --location -s -X GET "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients" \
  --header "Authorization: Bearer $NEW_TOKEN" \
  | jq -r ".[] | select(.clientId==\"$KEYCLOAK_CLIENT_ID\") | .id")
  echo "=> SAML client UUID: '$CLIENT_UUID'"
  SAML_ENDPOINT="$KEYCLOAK_URL/realms/$KEYCLOAK_REALM/protocol/saml/descriptor"
  echo "=> SAML 2.0 endpoint URL: '$SAML_ENDPOINT'"
}

# Create custom mappers
create_mapper() {
  local MAPPER_NAME="$1"
  local TOKEN_CLAIM_NAME="$2"
  local CLAIM_VALUE="$3"
  local CLAIM_JSON_TYPE="$4"

  curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $NEW_TOKEN" \
    -d '{
      "name": "'"$MAPPER_NAME"'",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-hardcoded-claim-mapper",
      "config": {
        "claim.name": "'"$TOKEN_CLAIM_NAME"'",
        "claim.value": "'"$CLAIM_VALUE"'",
        "jsonType.label": "'"$CLAIM_JSON_TYPE"'",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "lightweight.claim": "false",
        "userinfo.token.claim": "true",
        "access.tokenResponse.claim": "false",
        "introspection.token.claim": "true"
      }
    }' \
    "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID/protocol-mappers/models"
  echo "Mapper '$MAPPER_NAME' added to client scope '$KEYCLOAK_CLIENT_SCOPE_NAME'."
}

# start:
NEW_TOKEN=$(get_access_token)
create_realm
create_user

if [[ $KEYCLOAK_CLIENT_TYPE =~ ^(oidc|OIDC)$ ]]; then
    create_oidc_client
elif [[ $KEYCLOAK_CLIENT_TYPE =~ ^(saml|SAML)$ ]]; then
    create_saml_client
else
    echo "##### The client type provided '$KEYCLOAK_CLIENT_TYPE' is not valid, proceeding with OIDC by default"
    create_oidc_client
fi

if [ "$CREATE_CUSTOM_MAPPERS" = "true" ]; then
  echo "CREATE_CUSTOM_MAPPERS is set to true, creating mappers..."
    create_mapper "UID" "UID" "123" "String"
    create_mapper "GID" "GID" "456" "String" 
    create_mapper "SUPPLEMENTARYGROUPS" "SUPPLEMENTARYGROUPS" "[123,342]" "JSON"
else
  echo "CREATE_CUSTOM_MAPPERS is not set to true, skipping."
fi

echo "#### post install script finished :)"