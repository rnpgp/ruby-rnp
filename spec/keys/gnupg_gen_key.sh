#!/bin/bash
#
# gnupg-gen-key.sh by <ronald.tse@ribose.com>
#
# Generates a `compliant' GnuPG key for testing purposes.
# Compliant means:
# - RSA 4096 bits
# - PGPv4 key with subkey for encryption
# - desired cipher/hash usage preferences
#
# Expected behavior:
# When working:
#   Outputs private and public keys in ASCII armored format.
#

readonly __progname=$(basename $0)

errx() {
  echo -e "$__progname: $@" >&2
  exit 1
}

usage() {
  echo "usage: $__progname" >&2
  exit 1
}

creation_date() {
  echo "$(date -u '+%Y%m%dT%H%M%S')"
}

expiry_date() {
  if date --version >/dev/null 2>&1 ; then
    echo "$(date -u -d '+2 years' '+%Y%m%dT%H%M%S')"
  else
    echo "$(date -u -v+2y '+%Y%m%dT%H%M%S')"
  fi
}

is_linux() {
  if [ "$(uname -s)" == "Linux" ]; then
    echo "true" && return
  fi
  echo "false"
}

main() {

  export GNUPGHOME="$(mktemp -d)"

  echo "[gnupg_gen_key] Setting GNUPGHOME to '${GNUPGHOME}', copy the following line if necessary for debug." >&2
  echo "[gnupg_gen_key] \"export GNUPGHOME=${GNUPGHOME}\"" >&2

  readonly key_parms_path="$(mktemp)"

  creation_date="$(creation_date)"
  expiry_date="$(expiry_date)"

  if [ -z "${creation_date}" ] || [ -z "${expiry_date}" ]; then
    errx "Date generation failed."
  fi

  cat > ${key_parms_path} <<EOF
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: encrypt
Name-Real: NetPGP Test
Name-Comment: Interoperability test
Name-Email: netpgp@ribose.com
Expire-Date: ${expiry_date}
Creation-Date: ${creation_date}
Preferences: SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
EOF

  echo "[gnupg_gen_key] Generated GnupgKeyParms file to '${key_parms_path}'." >&2
  echo "[gnupg_gen_key] Key generation params are:
\"
$(cat ${key_parms_path})
\"" >&2

  echo "[gnupg_gen_key] Generating GNUPG key..." >&2
  if [ "$(is_linux)" == "true" ]; then
    available_entropy="$(cat /proc/sys/kernel/random/entropy_avail)"

    echo "[gnupg_gen_key] Entropy available: ${available_entropy}" >&2
    if [[ ${available_entropy} < 2000 ]]; then
      echo "[gnupg_gen_key] WARNING: Only ${available_entropy} units of entropy available in this system and may cause this step to run for a long time." >&2
    fi
  fi

  echo "[gnupg_gen_key] Note: If this step takes too long your system probably doesn't have enough entropy." >&2
  echo "[gnupg_gen_key]       If you're in a container try restarting the container with -v /dev/urandom:/dev/random of the host." >&2
  echo "[gnupg_gen_key]       Or view /proc/sys/kernel/random/entropy_avail to see how much is available." >&2
  generate_key_output="$(gpg --batch --gen-key ${key_parms_path} 2>&1)"

  if [ -z "${generate_key_output}" ]; then
    errx "Key generation failed."
  fi

  echo "[gnupg_gen_key] Generate key output below:
\"
${generate_key_output}
\"" >&2
  #fingerprint="$(echo ${generate_key_output}\")"

  echo "[gnupg_gen_key] Key generated." >&2

  keyid="$(gpg --list-keys | grep 4096R | grep pub | cut -d '/' -f 2 | cut -d ' ' -f 1)"

  if [ -z "${keyid}" ]; then
    errx "Unable to find KeyID using 'gpg --list-keys' command!"
  fi

  echo "[gnupg_gen_key] Key's 'KeyID' is (${keyid})."

  public_key="$(gpg -a --export ${keyid})"

  if [ -z "${public_key}" ]; then
    errx "Unable to export public key with KeyID (${keyid}) using 'gpg -a --export' command!"
  fi

  echo "[gnupg_gen_key] Public key is:
\"
${public_key}
\"
  "

  private_key="$(gpg -a --export-secret-keys ${keyid})"

  if [ -z "${private_key}" ]; then
    errx "Unable to export private key with KeyID (${keyid}) using 'gpg -a --export-secret-keys' command!"
  fi

  echo "[gnupg_gen_key] Private key is:
\"
${private_key}
\"
  "

  return 0
}

main $@

exit $?
