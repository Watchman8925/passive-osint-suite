# This file describes required GitHub secrets for automated Docker supply chain workflows

DOCKERHUB_USERNAME: Your Docker Hub username
DOCKERHUB_TOKEN: Your Docker Hub access token (create at https://hub.docker.com/settings/security)

# How to add secrets:
# 1. Go to your GitHub repository > Settings > Secrets and variables > Actions
# 2. Click "New repository secret"
# 3. Add each secret above with its value

# These secrets enable automated build, signing, and push in the workflow:
# .github/workflows/docker-supply-chain.yml
