require 'ffi'

require_relative 'enums'
require_relative 'constants'

module LibNetPGP
  extend FFI::Library

  class PGPErrCode < FFI::Struct
    layout :errcode, :pgp_errcode_t
  end

  class PGPPTag < FFI::Struct
    layout :new_format, :uint,
           :type, :uint, #:pgp_content_enum?
           :length_type, :pgp_ptag_of_lt_t,
           :length, :uint,
           :position, :uint,
           :size, :uint
  end

  class PGPDSAPubKey < FFI::Struct
    layout :p, :pointer,
           :q, :pointer,
           :g, :pointer,
           :y, :pointer
  end

  class PGPRSAPubKey < FFI::Struct
    layout :n, :pointer,
           :e, :pointer
  end

  class PGPElGamalPubKey < FFI::Struct
    layout :p, :pointer,
           :g, :pointer,
           :y, :pointer
  end

  class PGPPubKeyU < FFI::Union
    layout :dsa, PGPDSAPubKey,
           :rsa, PGPRSAPubKey,
           :elgamal, PGPElGamalPubKey
  end

  class PGPPubKey < FFI::Struct
    layout :version,    :pgp_version_t,
           :birthtime,  :time_t,
           :duration,   :time_t,
           :days_valid, :uint,
           :alg,        :pgp_pubkey_alg_t,
           :key, PGPPubKeyU
  end

  class PGPData < FFI::Struct
    layout :len, :size_t,
           :contents, :pointer,
           :mmapped, :uint8
  end

  class PGPRSASig < FFI::Struct
    layout :sig, :pointer
  end

  class PGPDSASig < FFI::Struct
    layout :r, :pointer,
           :s, :pointer
  end

  class PGPElGamalSig < FFI::Struct
    layout :r, :pointer,
           :s, :pointer
  end

  class PGPSigInfoU < FFI::Union
    layout :rsa,     PGPRSASig,
           :dsa,     PGPDSASig,
           :elgamal, PGPElGamalSig,
           :unknown, PGPData
  end

  class PGPSigInfo < FFI::Struct
    layout :version,      :pgp_version_t,
           :type,         :pgp_sig_type_t,
           :birthtime,    :time_t,
           :duration,     :time_t,
           :signer_id,    [:uint8, PGP_KEY_ID_SIZE],
           :key_alg,      :pgp_pubkey_alg_t,
           :hash_alg,     :pgp_hash_alg_t,
           :sig,          PGPSigInfoU,
           :v4_hashlen,   :size_t,
           :v4_hashed,    :pointer,
           :flags,        :uint # bitfields
  end

  class PGPSig < FFI::Struct
    layout :info,           PGPSigInfo,
           :hash2,          [:uint8, 2],
           :v4_hashstart,   :size_t,
           :hash,           :pointer
  end

  class PGPSSRaw < FFI::Struct
    layout :tag,    :pgp_content_enum,
           :length, :size_t,
           :raw,    :pointer
  end

  class PGPSSTrust < FFI::Struct
    layout :level,  :uint8,
           :amount, :uint8
  end

  class PGPSSNotation < FFI::Struct
    layout :flags, PGPData,
           :name,  PGPData,
           :value, PGPData
  end

  class PGPSubPacket < FFI::Struct
    layout :length, :size_t,
           :raw,    :pointer
  end

  class PGPOnePassSig < FFI::Struct
    layout :version,    :uint8,
           :sig_type,   :pgp_sig_type_t,
           :hash_alg,   :pgp_hash_alg_t,
           :key_alg,    :pgp_pubkey_alg_t,
           :keyid,      [:uint8, PGP_KEY_ID_SIZE],
           :nested,     :uint
  end

  class PGPSSRevocationKey < FFI::Struct
    layout :class,       :uint8,
           :algid,       :uint8,
           :fingerprint, [:uint8, PGP_FINGERPRINT_SIZE]
  end

  class PGPLitDataHeader < FFI::Struct
    layout :format,   :pgp_litdata_enum,
           :filename, [:char, 256],
           :mtime,    :time_t
  end

  class PGPLitDataBody < FFI::Struct
    layout :length, :uint,
           :data,   :pointer,
           :mem,    :pointer
  end

  class PGPDynBody < FFI::Struct
    layout :length, :uint,
           :data,   :pointer
  end

  class PGPSSSigTarget < FFI::Struct
    layout :pka_alg,  :pgp_pubkey_alg_t,
           :hash_alg, :pgp_hash_alg_t,
           :hash,     PGPData
  end

  class PGPSSRevocation < FFI::Struct
    layout :code,   :uint8,
           :reason, :string
  end

  class PGPRSASecKey < FFI::Struct
    layout :d, :pointer,
           :p, :pointer,
           :q, :pointer,
           :u, :pointer
  end

  class PGPDSASecKey < FFI::Struct
    layout :x, :pointer
  end

  class PGPElGamalSecKey < FFI::Struct
    layout :x, :pointer
  end

  class PGPSecKeyU < FFI::Union
    layout :rsa,      PGPRSASecKey,
           :dsa,      PGPDSASecKey,
           :elgamal,  PGPElGamalSecKey
  end

  class PGPSecKey < FFI::Struct
    layout :pubkey,         PGPPubKey,
           :s2k_usage,      :pgp_s2k_usage_t,
           :s2k_specifier,  :pgp_s2k_specifier_t,
           :alg,            :pgp_symm_alg_t,
           :hash_alg,       :pgp_hash_alg_t,
           :salt,           [:uint8, PGP_SALT_SIZE],
           :octetc,         :uint,
           :iv, [:uint8,    PGP_MAX_BLOCK_SIZE],
           :key,            PGPSecKeyU,
           :checksum,       :uint,
           :checkhash,      :pointer
  end

  class PGPHeaders < FFI::Struct
    layout :headers, :pointer,
           :headerc, :uint
  end

  class PGPArmourHeader < FFI::Struct
    layout :type,    :string,
           :headers, PGPHeaders
  end

  class PGPFixedBody < FFI::Struct
    layout :length, :uint,
           :data,   [:uint8, 8192]
  end

  class PGPHash < FFI::Struct
    layout :alg,      :pgp_hash_alg_t,
           :size,     :size_t,
           :name,     :string,
           :init,     :pointer,
           :add,      :pointer,
           :data,     :pointer
  end

  class PGPPKSessKeyParamsRSA < FFI::Struct
    layout :encrypted_m, :pointer,
           :m,           :pointer
  end

  class PGPPKSessKeyParamsElGamal < FFI::Struct
    layout :g_to_k,       :pointer,
           :encrypted_m,  :pointer
  end

  class PGPPKSessKeyParamsU < FFI::Union
    layout :rsa,     PGPPKSessKeyParamsRSA,
           :elgamal, PGPPKSessKeyParamsElGamal
  end

  class PGPPKSessKey < FFI::Struct
    layout :version,    :uint,
           :key_id,     [:uint8, PGP_KEY_ID_SIZE],
           :alg,        :pgp_pubkey_alg_t,
           :params,     PGPPKSessKeyParamsU,
           :symm_alg,   :pgp_symm_alg_t,
           :key,        [:uint8, PGP_MAX_KEY_SIZE],
           :checksum,  :uint16
  end

  class PGPSecKeyPassphrase < FFI::Struct
    layout :seckey,     :pointer,
           :passphrase, :pointer
  end

  class PGPGetSecKey < FFI::Struct
    layout :seckey,     :pointer,
           :pk_sesskey, :pointer
  end

  class PGPContents < FFI::Union
    layout :error,                :string,
           :errcode,              PGPErrCode,
           :ptag,                 PGPPTag,
           :pubkey,               PGPPubKey,
           :trust,                PGPData,
           :userid,               :string,
           :userattr,             PGPData,
           :sig,                  PGPSig,
           :ss_raw,               PGPSSRaw,
           :ss_trust,             PGPSSTrust,
           :ss_revocable,         :uint,
           :ss_time,              :time_t,
           :ss_issuer,            [:uint8, PGP_KEY_ID_SIZE],
           :ss_notation,          PGPSSNotation,
           :packet,               PGPSubPacket,
           :compressed,           :pgp_compression_type_t,
           :one_pass_sig,         PGPOnePassSig,
           :ss_skapref,           PGPData,
           :ss_hashpref,          PGPData,
           :ss_zpref,             PGPData,
           :ss_key_flags,         PGPData,
           :ss_key_server_prefs,  PGPData,
           :ss_primary_userid,    :uint,
           :ss_regexp,            :string,
           :ss_policy,            :string,
           :ss_keyserv,           :string,
           :ss_revocation_key,    PGPSSRevocationKey,
           :ss_userdef,           PGPData,
           :ss_unknown,           PGPData,
           :litdata_header,       PGPLitDataHeader,
           :litdata_body,         PGPLitDataBody,
           :mdc,                  PGPDynBody,
           :ss_features,          PGPData,
           :ss_sig_target,        PGPSSSigTarget,
           :ss_embedded_sig,      PGPData,
           :ss_revocation,        PGPSSRevocation,
           :seckey,               PGPSecKey,
           :ss_signer,            :pointer,
           :armour_header,        PGPArmourHeader,
           :armour_trailer,       :string,
           :cleartext_head,       PGPHeaders,
           :cleartext_body,       PGPFixedBody,
           :cleartext_trailer,    PGPHash,
           :unarmoured_text,      PGPDynBody,
           :pk_sesskey,           PGPPKSessKey,
           :skey_passphrase,      PGPSecKeyPassphrase,
           :se_ip_data_header,    :uint,
           :se_ip_data_body,      PGPDynBody,
           :se_data_body,         PGPFixedBody,
           :get_seckey,           PGPGetSecKey
  end

  class PGPPacket < FFI::Struct
    layout :tag,      :pgp_content_enum,
           :critical, :uint8,
           :u,        PGPContents
  end

  callback :pgp_reader_func,
           [:pointer, :pointer, :size_t, :pointer, :pointer, :pointer], :int
  callback :pgp_reader_destroyer,
           [:pointer], :void
  callback :pgp_cbfunc_t,
           [PGPPacket.by_ref, :pointer],
           :pgp_cb_ret_t

  class PGPReader < FFI::Struct
    layout :reader,      :pgp_reader_func,
           :destroyer,   :pgp_reader_destroyer,
           :arg,         :pointer,
           :accumulate,  :uint, # bitfield
           :accumulated, :pointer,
           :asize,       :uint,
           :alength,     :uint,
           :position,    :uint,
           :next,        :pointer,
           :parent,      :pointer
  end

  class PGPCryptInfo < FFI::Struct
    layout :passphrase,     :pointer,
           :secring,        :pointer,
           :keydata,        :pointer,
           :getpassphrase,  :pointer,
           :pubring,        :pointer
  end

  class PGPPrintState < FFI::Struct
    layout :unarmoured,   :uint,
           :skipipng,     :uint,
           :indent,       :int
  end

  class PGPCBData < FFI::Struct
    layout :cbfunc,      :pointer,
           :arg,         :pointer,
           :errors,      :pointer,
           :next,        :pointer,
           :output,      :pointer,
           :io,          :pointer,
           :passfp,      :pointer,
           :cryptinfo,   PGPCryptInfo,
           :printstate,  PGPPrintState,
           :sshseckey,   :pointer,
           :numtries,    :int,
           :gotpass,     :int
  end

  class PGPCrypt < FFI::Struct
    PGP_MAX_BLOCK_SIZE = 16
    layout :alg,                :pgp_symm_alg_t,
           :blocksize,          :size_t,
           :keysize,            :size_t,
           :set_iv,             :pointer,
           :set_crypt_key,      :pointer,
           :base_init,          :pointer,
           :decrypt_resync,     :pointer,
           :block_encrypt,      :pointer,
           :block_decrypt,      :pointer,
           :cfb_encrypt,        :pointer,
           :cfb_decrypt,        :pointer,
           :decrypt_finish,     :pointer,
           :iv,                 [:uint8, PGP_MAX_BLOCK_SIZE],
           :civ,                [:uint8, PGP_MAX_BLOCK_SIZE],
           :siv,                [:uint8, PGP_MAX_BLOCK_SIZE],
           :key,                [:uint8, PGP_MAX_KEY_SIZE],
           :num,                :int,
           :encrypt_key,        :pointer,
           :decrypt_key,        :pointer
  end

  class PGPStream < FFI::ManagedStruct
    NTAGS = 0x100
    layout :ss_raw,     [:uint8, NTAGS / 8],
           :ss_parsed,  [:uint8, NTAGS / 8],
           :readinfo,   PGPReader,
           :cbinfo,     PGPCBData,
           :errors,     :pointer,
           :io,         :pointer,
           :decrypt,    PGPCrypt,
           :cryptinfo,  PGPCryptInfo,
           :hashc,      :size_t,
           :hashes,     :pointer,
           :flags,      :uint, # bitfields
           :virtualc,   :uint,
           :virtualoff, :uint,
           :virtualpkt, :pointer

    def self.release(ptr)
      LibNetPGP::pgp_stream_delete(ptr)
    end
  end

  class PGPIO < FFI::Struct
    layout :outs, :pointer,
           :errs, :pointer,
           :res,  :pointer
  end

  class PGPKeyring < FFI::ManagedStruct
    layout :keyc,       :uint,
           :keyvsize,   :uint,
           :keys,       :pointer,
           :hashtype,   :pgp_hash_alg_t

    def self.release(ptr)
      LibNetPGP::pgp_keyring_free(ptr)
      LibC::free(ptr)
    end

   end

  class PGPKeyDataKey < FFI::Union
    layout :pubkey, PGPPubKey,
           :seckey, PGPSecKey
  end

  class PGPFingerprint < FFI::Struct
    layout :fingerprint, [:uint8, PGP_FINGERPRINT_SIZE],
           :length,      :uint,
           :hashtype,    :pgp_hash_alg_t
  end

  class PGPRevoke < FFI::Struct
    layout :uid,    :uint32,
           :code,   :uint8,
           :reason, :string
  end

  class PGPKey < FFI::Struct
    layout :uidc,             :uint,
           :uidvsize,         :uint,
           :uids,             :pointer,
           :packetc,          :uint,
           :packetvsize,      :uint,
           :packets,          :pointer,
           :subsigc,          :uint,
           :subsigvsize,      :uint,
           :subsigs,          :pointer,
           :revokec,          :uint,
           :revokevsize,      :uint,
           :revokes,          :pointer,
           :type,             :pgp_content_enum,
           :key,              PGPKeyDataKey,
           :sigkey,           PGPPubKey,
           :sigid,            [:uint8, PGP_KEY_ID_SIZE],
           :sigfingerprint,   PGPFingerprint,
           :enckey,           PGPPubKey,
           :encid,            [:uint8, PGP_KEY_ID_SIZE],
           :encfingerprint,   PGPFingerprint,
           :uid0,             :uint32,
           :revoked,          :uint8,
           :revocation,       PGPRevoke
  end

  class PGPMemory < FFI::Struct
    layout :buf,        :pointer,
           :length,     :size_t,
           :allocated,  :size_t,
           :mmapped,    :uint
  end

  class PGPValidation < FFI::Struct
    layout :validc,         :uint,
           :valid_sigs,     :pointer,
           :invalidc,       :uint,
           :invalid_sigs,   :pointer,
           :unknownc,       :uint,
           :unknown_sigs,   :pointer,
           :birthtime,      :time_t,
           :duration,       :time_t
  end

end

