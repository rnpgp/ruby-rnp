set -euxo pipefail

mkdir -p installs
LOCAL_INSTALLS=/tmp/rnp-local-installs
ln -s "$GITHUB_WORKSPACE/installs" /tmp/rnp-local-installs
echo "CACHE_DIR=installs" >> $GITHUB_ENV
echo "BOTAN_INSTALL=$GITHUB_WORKSPACE/installs/botan" >> $GITHUB_ENV
echo "JSONC_INSTALL=$GITHUB_WORKSPACE/installs/jsonc" >> $GITHUB_ENV
echo "RNP_INSTALL=$GITHUB_WORKSPACE/installs/rnp" >> $GITHUB_ENV
