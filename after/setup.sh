
#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status

echo ""
# Start Keycloak and the Flask app using Docker Compose
echo "[*] Starting Keycloak and the Flask app..."
docker compose up -d --build

echo ""
# Wait until Keycloak is ready to accept connections
echo "[*] Waiting for Keycloak to be ready..."
until curl -s http://localhost:8080/realms/master > /dev/null; do
    echo "Waiting for Keycloak to start..."
    sleep 5
done

echo ""
# Configure Keycloak using its REST API
echo "[*] Configuring Keycloak via REST API..."

echo ""
# Obtain an admin access token from Keycloak
export ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r .access_token)

# Check if the 'FintechApp' realm already exists
REALM_EXISTS=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/admin/realms | jq -r '.[] | select(.realm=="FintechApp") | .realm')
if [ "$REALM_EXISTS" == "FintechApp" ]; then
  echo "[!] Realm 'FintechApp' already exists. Skipping creation."
  echo ""
else
  # Create the 'FintechApp' realm using the provided configuration
  curl -s -X POST "http://localhost:8080/admin/realms" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d @realm-config.json
  echo "[✔] Realm 'FintechApp' created."
  echo ""
fi


echo "[*] Populating LDAP with seed data..."
cat seed.ldif | docker exec -i "$(docker compose ps -q ldap)" ldapadd -x -D "cn=admin,dc=example,dc=com" -w adminpw


# Test access token retrieval for the test user
echo "[*] Testing access token retrieval..."
RESPONSE=$(curl -s -X POST "http://localhost:8080/realms/FintechApp/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=flask-client" \
  -d "client_secret=secret" \
  -d "username=testuser" \
  -d "password=password")

# Print the token response in a readable format
echo "$RESPONSE" | jq

# Print completion and usage instructions
echo "[✔] Setup complete. Access the Flask app at: http://localhost:15000"
echo "[ℹ️ ] To test manually:"
echo "curl -H \"Authorization: Bearer <access_token>\" http://localhost:15000"

echo "[*] Starting Keycloak and the Flask app..."
docker compose up -d --build

echo "[*] Waiting for Keycloak to be ready..."
until curl -s http://localhost:8080/realms/master > /dev/null; do
    echo "Waiting for Keycloak to start..."
    sleep 5
done

echo "[*] Configuring Keycloak via REST API..."

# Get admin token
export ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r .access_token)

# Check and create realm
REALM_EXISTS=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/admin/realms | jq -r '.[] | select(.realm=="FintechApp") | .realm')
if [ "$REALM_EXISTS" == "FintechApp" ]; then
  echo "[!] Realm 'FintechApp' already exists. Skipping creation."
else
  curl -s -X POST "http://localhost:8080/admin/realms" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d @realm-config.json
  echo "[✔] Realm 'FintechApp' created."
fi

echo "[*] Testing access token retrieval..."
RESPONSE=$(curl -s -X POST "http://host.docker.internal:8080/realms/FintechApp/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=flask-client" \
  -d "client_secret=secret" \
  -d "username=testuser" \
  -d "password=password")

echo ""
# Print the token response in a readable format
export TESTUSER_ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r .access_token)
curl -H "Authorization: Bearer $TESTUSER_ACCESS_TOKEN" http://host.docker.internal:15000
echo "$TESTUSER_ACCESS_TOKEN" > testuser_access_token.txt

echo ""
# Print the token response in a readable format
echo "$RESPONSE" | jq

echo ""
echo "[*] Testing access token retrieval for nonexisting user..."
RESPONSE=$(curl -s -X POST "http://host.docker.internal:8080/realms/FintechApp/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=flask-client" \
  -d "client_secret=secret" \
  -d "username=baduser" \
  -d "password=badpassword")

echo ""
# Print the token response in a readable format
echo "$RESPONSE" | jq

echo ""
echo "[✔] Setup complete. Access the Flask app at: http://host.docker.internal:15000"
echo "[ℹ️ ] To test manually:"
echo "curl -H \"Authorization: Bearer <access_token>\" http://host.docker.internal:15000"
