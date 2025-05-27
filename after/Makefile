# Makefile

# --- Phony Targets ---
.PHONY: all up down reset logs build sast image-scan dast host-scan all-scans clean check_app_ready

# --- Configuration Variables ---
# Your existing DOCKER_COMPOSE variable
DOCKER_COMPOSE := $(shell command -v docker-compose > /dev/null && echo docker-compose || echo docker compose)

# Security-related variables
APP_IMAGE_NAME := my-python-app:latest # Make sure this matches your Dockerfile's image name
APP_SRC_DIR := app # Directory containing your Python application source code (e.g., app.py, requirements.txt)
APP_CONTAINER_NAME := my-running-python-app # Name of the container for your Python app as defined in docker-compose.yml
APP_CONTAINER_PORT_INTERNAL := 5000 # Port your Python app listens on inside the container
APP_CONTAINER_PORT_HOST := 15000      # Port mapped to your host for external access (for DAST)
ZAP_REPORT_DIR := zap_reports
ZAP_DOCKER_IMAGE := zaproxy/zap-stable # <--- UPDATED: Using the new official ZAP Docker image
TESTUSER_ACCESS_TOKEN = $(shell cat testuser_access_token.txt)
# --- Your Existing Lab Targets ---
up:
	@echo "[*] Starting Lab 1 (Keycloak + Flask App)..."
	@bash setup.sh
	@make read_variables

down:
	@echo "[*] Stopping and removing all lab containers and volumes..."
	@$(DOCKER_COMPOSE) down -v

reset: down
	@echo "[*] Resetting lab environment..."
	@rm -rf keycloak_data
	@docker system prune -f
	@bash setup.sh

logs:
	@$(DOCKER_COMPOSE) logs -f

# --- Security Scan Targets ---

# Build Application Image
# This assumes your Dockerfile is in the project root and builds 'my-python-app:latest'
# and your docker-compose.yml has a service named 'app'
build:
	@echo "--- Building $(APP_IMAGE_NAME) ---"
	@$(DOCKER_COMPOSE) build flask-app # Build only the 'app' service

# Static Code Analysis (SAST)
# Analyzes your source code for security vulnerabilities without running it.
# Uses Bandit, which is specific for Python security analysis.
sast:
	@echo "\n--- Running Static Code Analysis (Bandit) on $(APP_SRC_DIR) ---"
	@docker run --rm \
		-v "$(PWD)/$(APP_DIR)":/app \
		python:3.13-alpine sh -c "pip install --no-cache-dir bandit && bandit -r /app" \
		> static_code_analysis.log || true
	@echo "Static code analysis complete. Review findings in static_code_analysis.log."

# Docker Image Vulnerability Scan
# Scans the built Docker image for known vulnerabilities in OS packages and dependencies.
# Uses Trivy.
image-scan: 
	@echo "\n--- Running Docker Image Vulnerability Scan on $(APP_IMAGE_NAME) with Docker Scout ---"
	@docker scout recommendations $(APP_IMAGE_NAME)
	@echo "Image vulnerability scan complete. Review findings above."

# Helper target to check if the app container is ready for DAST
check_app_ready:
	@echo "Waiting for $(APP_CONTAINER_NAME) to be accessible on http://localhost:$(APP_CONTAINER_PORT_HOST)..."
	@until curl -sS http://localhost:$(APP_CONTAINER_PORT_HOST) > /dev/null; do \
		echo "App not yet accessible, waiting..."; \
		sleep 2; \
	done
	@echo "$(APP_CONTAINER_NAME) is accessible!"

# Dynamic Application Security Testing (DAST)
# This target assumes your 'app' service is already running via 'make up'.
# It waits for the app to be accessible before running scans.
dast: check_app_ready
	@echo "\n--- Running DAST Scan (OWASP ZAP Baseline) ---"
	@mkdir -p $(ZAP_REPORT_DIR)
	@docker run --rm \
		-v "$(PWD)/$(ZAP_REPORT_DIR):/zap/wrk:rw" \
		$(ZAP_DOCKER_IMAGE) zap-baseline.py \
		-t http://host.docker.internal:$(APP_CONTAINER_PORT_HOST) \
		-r zap_baseline_report.html \
		-z "-config replacer.full_list(0).description=authheader  \
			-config replacer.full_list(0).enabled=true \
			-config replacer.full_list(0).matchtype=REQ_HEADER \
			-config replacer.full_list(0).matchstr=Authorization \
			-config replacer.full_list(0).replacement='Bearer $(TESTUSER_ACCESS_TOKEN)'" \
		> zap_dast.log || true		

	@echo "ZAP baseline scan complete. Report saved to zap_baseline_report.html"

# Host Security Checks
# Checks the Docker host's security configuration against best practices (CIS Benchmarks).
# Uses Docker Bench for Security.
host-security-scan:
	# @if ! command -v lynis >/dev/null 2>&1; then \
	#     echo "Lynis is not installed. Installing with Homebrew..."; \
	#     brew install lynis; \
	# fi
	# @echo "Running Lynis host security scan in non-interactive mode..."
	# @sudo lynis audit system --quick --no-log --no-colors --quiet --cronjob
	# @echo "Host security scan complete. Review findings above."
	# @echo "Note: Lynis must be installed directly on your host (e.g., 'sudo lynis audit system')."
	@echo "Running Docker Bench for Security..."
	# Mount the Docker socket to allow Docker Bench to inspect the Docker daemon.
	# This requires elevated privileges on the host.
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker/docker-bench-security > host_scan_report.log
# Master Target for All Scans
# Runs your lab setup, then all security scans.
up-and-scan-all: up sast image-scan dast host-security-scan
	@echo "\n--- All security scans complete! ---"
	@echo "Remember to review all reports and terminal outputs."
	@echo "To stop all lab services, run 'make down'."
	@rm -f testuser_access_token.txt # Clean up the access token file

# --- Cleanup ---
# Modified clean target to also remove ZAP reports
clean: down
	@echo "[*] Resetting lab environment and cleaning up scan reports..."
	@make down # Ensure all containers are stopped before cleanup
	@rm -rf keycloak_data
	@docker system prune -f
	@rm -rf $(ZAP_REPORT_DIR) # Added cleanup for ZAP reports
	@rm -f testuser_access_token.txt # Clean up the access token file
	@rm -f host_scan_report.log # Clean up host scan report
	@rm -f zap_reports/zap_baseline_report.html # Clean up ZAP baseline report
	@rm -f static_code_analysis.log # Clean up static code analysis report
	@rm -f zap_dast.log # Clean up ZAP DAST log


# read the variables from setup.sh script post execution
read_variables:
	@echo "Reading variables from setup.sh..."
	@echo "Token is: \n" $(TESTUSER_ACCESS_TOKEN)
	@echo "Variables read successfully."