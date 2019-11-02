var N=null,E="",T="t",U="u",searchIndex={};
var R=["tv_sec","__high","__size","__align","__data","result","to_owned","clone_into","try_from","try_into","borrow_mut","type_id","borrow","typeid","__fsid_t","__sigset_t","timespec","__pthread_rwlock_arch_t","__pthread_internal_list","__pthread_mutex_s","__pthread_cond_s","__pthread_cond_s__bindgen_ty_1","__pthread_cond_s__bindgen_ty_1__bindgen_ty_1","__pthread_cond_s__bindgen_ty_2","__pthread_cond_s__bindgen_ty_2__bindgen_ty_1","pthread_mutexattr_t","pthread_condattr_t","pthread_attr_t","pthread_mutex_t","pthread_cond_t","pthread_rwlock_t","pthread_rwlockattr_t","pthread_barrier_t","pthread_barrierattr_t","max_align_t","tls_config","formatter","timeval","TLS major/minor protocol version.","TLS async I/O.","OCSP response (RFC 6960 Section 2.3).","OCSP certificate (RFC 6960 Section 2.2).","CRL (RFC 5280 Section 5.3.1).","TLS session.","tlsconfig","Build new [`TlsConfig`] object and return a configured…","Set the ALPN protocols that are supported.","Set the CA file.","Set the CA from memory.","Set the list of cipher that may be used.","Set the CRL file.","Set the CRL from memory.","Set the parameters of an Diffie-Hellman Ephemeral (DHE)…","Set the curves of an Elliptic Curve Diffie-Hellman…","Add additional files of a public and private key pair and…","Add an additional public and private key pair and OCSP…","Disable certificate verification.","Disable server name verification.","Disable certificate validity checking.","Set which versions of the TLS protocol may be used.","Set a file descriptor to manage data for TLS sessions.","Set the session identifier for TLS sessions.","Set the lifetime for TLS sessions.","Enable all certificate verification.","verify_client","Enable client certificate verification.","verify_client_optional","Enable optional client certificate verification.","Set the certificate verification depth.","option","tlsreadcb","tlswritecb","string","systemtime","libtls::config","libtls::error","libtls::tls","last_error","to_error","TlsConfig","TlsConfigBuilder","TlsError","LastError","tls_config_set_ca_mem","TLS_PROTOCOL_TLSv1_0","TLS_PROTOCOL_TLSv1_1","TLS_PROTOCOL_TLSv1_2","TLS_PROTOCOL_TLSv1","TLS_PROTOCOLS_ALL","TLS_PROTOCOLS_DEFAULT","TLS_WANT_POLLIN","TLS_WANT_POLLOUT","TLS_OCSP_RESPONSE_SUCCESSFUL","TLS_OCSP_RESPONSE_MALFORMED","TLS_OCSP_RESPONSE_INTERNALERROR","TLS_OCSP_RESPONSE_TRYLATER","TLS_OCSP_RESPONSE_SIGREQUIRED","TLS_OCSP_RESPONSE_UNAUTHORIZED","TLS_OCSP_CERT_GOOD","TLS_OCSP_CERT_REVOKED","TLS_OCSP_CERT_UNKNOWN","TLS_CRL_REASON_UNSPECIFIED","TLS_CRL_REASON_KEY_COMPROMISE","TLS_CRL_REASON_CA_COMPROMISE","TLS_CRL_REASON_AFFILIATION_CHANGED","TLS_CRL_REASON_SUPERSEDED","TLS_CRL_REASON_CESSATION_OF_OPERATION","TLS_CRL_REASON_CERTIFICATE_HOLD","TLS_CRL_REASON_REMOVE_FROM_CRL","TLS_CRL_REASON_PRIVILEGE_WITHDRAWN","TLS_CRL_REASON_AA_COMPROMISE","TLS_MAX_SESSION_ID_LENGTH","TLS_TICKET_KEY_SIZE"];
searchIndex["libtls"]={"doc":"Rust bindings for [LibreSSL]'s [libtls] library.","i":[[17,"TLS_API","libtls","TLS API version.",N,N],[17,R[84],E,R[38],N,N],[17,R[85],E,R[38],N,N],[17,R[86],E,R[38],N,N],[17,R[87],E,R[38],N,N],[17,R[88],E,R[38],N,N],[17,R[89],E,R[38],N,N],[17,R[90],E,R[39],N,N],[17,R[91],E,R[39],N,N],[17,R[92],E,R[40],N,N],[17,R[93],E,R[40],N,N],[17,R[94],E,R[40],N,N],[17,R[95],E,R[40],N,N],[17,R[96],E,R[40],N,N],[17,R[97],E,R[40],N,N],[17,R[98],E,R[41],N,N],[17,R[99],E,R[41],N,N],[17,R[100],E,R[41],N,N],[17,R[101],E,R[42],N,N],[17,R[102],E,R[42],N,N],[17,R[103],E,R[42],N,N],[17,R[104],E,R[42],N,N],[17,R[105],E,R[42],N,N],[17,R[106],E,R[42],N,N],[17,R[107],E,R[42],N,N],[17,R[108],E,R[42],N,N],[17,R[109],E,R[42],N,N],[17,R[110],E,R[42],N,N],[17,R[111],E,R[43],N,N],[17,R[112],E,R[43],N,N],[5,"init",E,"Initialize global data structures.",N,[[],[R[5]]]],[0,"config",E,"TLS configuration for connections.",N,N],[3,R[79],R[74],"The TLS configuration context for [`Tls`] connections.",N,N],[3,R[80],E,"`TlsConfigBuilder` for [`TlsConfig`].",N,N],[5,"default_ca_cert_file",E,"Return path of the default CA file.",N,[[],["pathbuf"]]],[5,"parse_protocols",E,"Parse protocol string.",N,[[["str"]],[["u32"],[R[5],["u32"]]]]],[5,"load_file",E,"Load a certificate or key file.",N,[[[R[69],["str"]],["asref",["path"]],["path"],["str"]],[["vec",["u8"]],[R[5],["vec"]]]]],[5,"unload_file",E,"Securely unload file that was loaded into memory.",N,[[["vec",["u8"]],["u8"]]]],[11,"new",E,"Create a new configuration.",0,[[],[R[5]]]],[11,"add_keypair_file",E,"Add additional files of a public and private key pair.",0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"add_keypair_mem",E,"Add an additional public and private key pair from memory.",0,[[["self"]],[R[5]]]],[11,"add_keypair_ocsp_file",E,R[54],0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"add_keypair_ocsp_mem",E,R[55],0,[[["self"]],[R[5]]]],[11,"set_alpn",E,R[46],0,[[["self"],["str"]],[R[5]]]],[11,"set_ca_file",E,R[47],0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"set_ca_path",E,"Set the path that should be searched for the CA files.",0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"set_ca_mem",E,R[48],0,[[["self"]],[R[5]]]],[11,R[83],E,"Set the CA file from memory.",0,[[["self"]],[R[5]]]],[11,"set_cert_file",E,"Set the public certificate file.",0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"set_cert_mem",E,"Set the public certificate from memory.",0,[[["self"]],[R[5]]]],[11,"set_ciphers",E,R[49],0,[[["self"],["str"]],[R[5]]]],[11,"set_crl_file",E,R[50],0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"set_crl_mem",E,R[51],0,[[["self"]],[R[5]]]],[11,"set_dheparams",E,R[52],0,[[["self"],["str"]],[R[5]]]],[11,"set_ecdhecurve",E,"The `set_ecdhecurve` method was replaced by set_ecdhecurves.",0,[[["self"],["str"]],[R[5]]]],[11,"set_ecdhecurves",E,R[53],0,[[["self"],["str"]],[R[5]]]],[11,"set_key_file",E,"Set the private key file.",0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"set_key_mem",E,"Set the private key from memory.",0,[[["self"]],[R[5]]]],[11,"set_keypair_file",E,"Set the files of the public and private key pair.",0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"set_keypair_mem",E,"Set the public and private key pair from memory.",0,[[["self"]],[R[5]]]],[11,"set_keypair_ocsp_file",E,"Set the files of a public and private key pair and an OCSP…",0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"set_keypair_ocsp_mem",E,"Set the public and private key pair and an OCSP staple…",0,[[["self"]],[R[5]]]],[11,"set_ocsp_staple_mem",E,"Set the OCSP staple from memory.",0,[[["self"]],[R[5]]]],[11,"set_ocsp_staple_file",E,"Set the OCSP staple file.",0,[[["self"],["asref",["path"]],["path"]],[R[5]]]],[11,"set_protocols",E,R[59],0,[[["self"],["u32"]],[R[5]]]],[11,"set_session_fd",E,R[60],0,[[["self"],["rawfd"]],[R[5]]]],[11,"set_verify_depth",E,R[68],0,[[["self"],["usize"]],[R[5]]]],[11,"prefer_ciphers_client",E,"Prefer ciphers in the client's cipher list.",0,[[["self"]]]],[11,"prefer_ciphers_server",E,"Prefer ciphers in the servers's cipher list.",0,[[["self"]]]],[11,"insecure_noverifycert",E,R[56],0,[[["self"]]]],[11,"insecure_noverifyname",E,R[57],0,[[["self"]]]],[11,"insecure_noverifytime",E,R[58],0,[[["self"]]]],[11,"verify",E,R[63],0,[[["self"]]]],[11,"ocsp_require_stapling",E,"Require OCSP stapling.",0,[[["self"]]]],[11,R[64],E,R[65],0,[[["self"]]]],[11,R[66],E,R[67],0,[[["self"]]]],[11,"clear_keys",E,"Securely clear secret keys.",0,[[["self"]]]],[11,"set_session_id",E,R[61],0,[[["self"]],[R[5]]]],[11,"set_session_lifetime",E,R[62],0,[[["self"],["usize"]],[R[5]]]],[11,"add_ticket_key",E,"Add a key for the encryption and authentication of TLS…",0,[[["self"],["u32"]],[R[5]]]],[11,"new",E,"Return new `TlsConfigBuilder`.",1,[[],["self"]]],[11,"build",E,"Build new [`TlsConfig`] object.",1,[[["self"]],[[R[5],[R[44]]],[R[44]]]]],[11,"client",E,R[45],1,[[["self"]],[["tls"],[R[5],["tls"]]]]],[11,"server",E,R[45],1,[[["self"]],[["tls"],[R[5],["tls"]]]]],[11,"alpn",E,R[46],1,[[["self"],["str"]],["self"]]],[11,"ca_file",E,R[47],1,[[["self"],["asref",["path"]],["path"]],["self"]]],[11,"ca_path",E,"Set the CA path.",1,[[["self"],["asref",["path"]],["path"]],["self"]]],[11,"ca_mem",E,R[48],1,[[["self"]],["self"]]],[11,"ciphers",E,R[49],1,[[["self"],["str"]],["self"]]],[11,"crl_file",E,R[50],1,[[["self"],["asref",["path"]],["path"]],["self"]]],[11,"crl_mem",E,R[51],1,[[["self"]],["self"]]],[11,"dheparams",E,R[52],1,[[["self"],["str"]],["self"]]],[11,"ecdhecurves",E,R[53],1,[[["self"],["str"]],["self"]]],[11,"keypair_file",E,R[54],1,[[["self"],["asref",["path"]],["path"],[R[69]]],["self"]]],[11,"keypair_mem",E,R[55],1,[[["self"],[R[69]]],["self"]]],[11,"noverifycert",E,R[56],1,[[["self"]],["self"]]],[11,"noverifyname",E,R[57],1,[[["self"]],["self"]]],[11,"noverifytime",E,R[58],1,[[["self"]],["self"]]],[11,"protocols",E,R[59],1,[[["self"],["u32"]],["self"]]],[11,"session_fd",E,R[60],1,[[["self"],["rawfd"]],["self"]]],[11,"session_id",E,R[61],1,[[["self"]],["self"]]],[11,"session_lifetime",E,R[62],1,[[["self"],["usize"]],["self"]]],[11,"ticket_key",E,"See also",1,[[["self"],["u32"]],["self"]]],[11,"verify",E,R[63],1,[[["self"]],["self"]]],[11,R[64],E,R[65],1,[[["self"]],["self"]]],[11,R[66],E,R[67],1,[[["self"]],["self"]]],[11,"verify_depth",E,R[68],1,[[["self"],["usize"]],["self"]]],[0,"error","libtls","Error handling.",N,N],[4,R[81],R[75],"An error returned by [`Tls`] and [`TlsConfig`] methods.",N,N],[13,"CtxError",E,"`Tls` error.",2,N],[13,"ConfigError",E,"`TlsConfig` error.",2,N],[13,"IoError",E,"Generic operating system or I/O error.",2,N],[13,"NulError",E,"An interior nul byte was found.",2,N],[13,"NoError",E,"No error was reported.",2,N],[6,"Result",E,"A result type that is returning a TlsError.",N,N],[8,R[82],E,"Returns the last API error.",N,N],[10,R[77],E,"Return the last error of the underlying API.",3,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,R[78],E,"Returns the error string as an error object.",3,[[[R[72]]],[R[5]]]],[0,"tls","libtls","TLS connections, clients and servers.",N,N],[3,"Tls",R[76],"TLS connection clients and servers.",N,N],[6,"TlsReadCb",E,"Read callback for [`Tls::accept_cbs`] and…",N,N],[6,"TlsWriteCb",E,"Write callback for [`Tls::accept_cbs`] and…",N,N],[11,"client",E,"Create a new TLS client.",4,[[],[R[5]]]],[11,"server",E,"Create a new TLS server.",4,[[],[R[5]]]],[11,"configure",E,"Configure the TLS context.",4,[[["self"],[R[44]]],[R[5]]]],[11,"reset",E,"Reset the TLS connection.",4,[[["self"]]]],[11,"accept_fds",E,"Accept a new TLS connection on a pair of existing file…",4,[[["self"],["rawfd"]],[["tls"],[R[5],["tls"]]]]],[11,"accept_socket",E,"Accept a new TLS connection on a socket.",4,[[["self"],["rawfd"]],[["tls"],[R[5],["tls"]]]]],[11,"accept_io",E,"Accept a new TLS connection on an established connection.",4,[[["self"],[T]],[["tls"],[R[5],["tls"]]]]],[11,"accept_cbs",E,"Accept a new TLS connection with custom I/O callbacks.",4,[[["self"],[R[69]],[R[70]],[R[71]]],[["tls"],[R[5],["tls"]]]]],[11,"connect",E,"Initiate a new TLS connection.",4,[[["self"],["str"],[R[69],["str"]]],[R[5]]]],[11,"connect_fds",E,"Initiate a new TLS connection over a pair of existing file…",4,[[["self"],["rawfd"],["str"]],[R[5]]]],[11,"connect_servername",E,"Initiate a new TLS connection with a specified server name.",4,[[["self"],["str"],["tosocketaddrs"]],[R[5]]]],[11,"connect_socket",E,"Initiate a new TLS connection over an established socket.",4,[[["self"],["rawfd"],["str"]],[R[5]]]],[11,"connect_io",E,"Initiate a new TLS connection over an established…",4,[[["self"],[T],["str"]],[R[5]]]],[11,"connect_cbs",E,"Initiate a new TLS connection with custom I/O callbacks.",4,[[["self"],["str"],[R[69]],[R[70]],[R[71]]],[R[5]]]],[11,"handshake",E,"Explicitly perform the TLS handshake.",4,[[["self"]],[["isize"],[R[5],["isize"]]]]],[11,"read",E,"Read bytes from the TLS connection.",4,[[["self"]],[["isize"],[R[5],["isize"]]]]],[11,"write",E,"Write bytes to the TLS connection.",4,[[["self"]],[["isize"],[R[5],["isize"]]]]],[11,"close",E,"Close the connection.",4,[[["self"]],[["isize"],[R[5],["isize"]]]]],[11,"peer_cert_provided",E,"Check for peer certificate.",4,[[["self"]],["bool"]]],[11,"peer_cert_contains_name",E,"Check if the peer certificate includes a matching name.",4,[[["self"],["str"]],[["bool"],[R[5],["bool"]]]]],[11,"peer_cert_hash",E,"Return hash of the peer certificate.",4,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,"peer_cert_issuer",E,"Return the issuer of the peer certificate.",4,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,"peer_cert_subject",E,"Return the subject of the peer certificate.",4,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,"peer_cert_notbefore",E,"Return the start of the validity period of the peer…",4,[[["self"]],[[R[73]],[R[5],[R[73]]]]]],[11,"peer_cert_notafter",E,"Return the end of the validity period of the peer…",4,[[["self"]],[[R[73]],[R[5],[R[73]]]]]],[11,"peer_cert_chain_pem",E,"Return the PEM-encoded peer certificate.",4,[[["self"]],[["vec",["u8"]],[R[5],["vec"]]]]],[11,"conn_alpn_selected",E,"Return the selected ALPN protocol.",4,[[["self"]],[[R[72]],[R[69],[R[72]]]]]],[11,"conn_cipher",E,"Return the negotiated cipher suite.",4,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,"conn_servername",E,"Return the client's server name.",4,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,"conn_session_resumed",E,"Check if a TLS session has been resumed.",4,[[["self"]],["bool"]]],[11,"conn_version",E,"Return the negotiated TLS version as a string.",4,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,"ocsp_process_response",E,"Process a raw OCSP response.",4,[[["self"]],[R[5]]]],[11,"peer_ocsp_cert_status",E,"OCSP certificate status.",4,[[["self"]],[["isize"],[R[5],["isize"]]]]],[11,"peer_ocsp_crl_reason",E,"OCSP certificate revocation reason.",4,[[["self"]],[["isize"],[R[5],["isize"]]]]],[11,"peer_ocsp_next_update",E,"OCSP next update time.",4,[[["self"]],[[R[73]],[R[5],[R[73]]]]]],[11,"peer_ocsp_response_status",E,"OCSP response status.",4,[[["self"]],[["isize"],[R[5],["isize"]]]]],[11,"peer_ocsp_result",E,"Textual representation of the OCSP status code.",4,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,"peer_ocsp_revocation_time",E,"OCSP revocation time.",4,[[["self"]],[[R[73]],[R[5],[R[73]]]]]],[11,"peer_ocsp_this_update",E,"OCSP this update time.",4,[[["self"]],[[R[73]],[R[5],[R[73]]]]]],[11,"peer_ocsp_url",E,"OCSP validation URL.",4,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,"into",R[74],E,0,[[],[U]]],[11,"from",E,E,0,[[[T]],[T]]],[11,R[8],E,E,0,[[[U]],[R[5]]]],[11,R[9],E,E,0,[[],[R[5]]]],[11,R[10],E,E,0,[[["self"]],[T]]],[11,R[12],E,E,0,[[["self"]],[T]]],[11,R[11],E,E,0,[[["self"]],[R[13]]]],[11,"into",E,E,1,[[],[U]]],[11,"from",E,E,1,[[[T]],[T]]],[11,R[8],E,E,1,[[[U]],[R[5]]]],[11,R[9],E,E,1,[[],[R[5]]]],[11,R[10],E,E,1,[[["self"]],[T]]],[11,R[12],E,E,1,[[["self"]],[T]]],[11,R[11],E,E,1,[[["self"]],[R[13]]]],[11,"into",R[75],E,2,[[],[U]]],[11,"from",E,E,2,[[[T]],[T]]],[11,"to_string",E,E,2,[[["self"]],[R[72]]]],[11,R[8],E,E,2,[[[U]],[R[5]]]],[11,R[9],E,E,2,[[],[R[5]]]],[11,R[10],E,E,2,[[["self"]],[T]]],[11,R[12],E,E,2,[[["self"]],[T]]],[11,R[11],E,E,2,[[["self"]],[R[13]]]],[11,"into",R[76],E,4,[[],[U]]],[11,"from",E,E,4,[[[T]],[T]]],[11,R[8],E,E,4,[[[U]],[R[5]]]],[11,R[9],E,E,4,[[],[R[5]]]],[11,R[10],E,E,4,[[["self"]],[T]]],[11,R[12],E,E,4,[[["self"]],[T]]],[11,R[11],E,E,4,[[["self"]],[R[13]]]],[11,R[77],R[74],"Returns the configuration last error.",0,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,R[78],E,E,0,[[[R[72]]],[R[5]]]],[11,R[77],R[76],"Returns the last error of the TLS context.",4,[[["self"]],[[R[72]],[R[5],[R[72]]]]]],[11,R[78],E,E,4,[[[R[72]]],[R[5]]]],[11,"drop",R[74],"Free the configuration object. This should only happen…",0,[[["self"]]]],[11,"drop",R[76],"The `drop` method frees the [`Tls`] context and forcibly…",4,[[["self"]]]],[11,"default",R[74],E,1,[[],["tlsconfigbuilder"]]],[11,"from",E,E,0,[[],["self"]]],[11,"from",R[75],E,2,[[["error"]],["self"]]],[11,"from",E,E,2,[[["nulerror"]],["self"]]],[11,"from",E,E,2,[[["tryfrominterror"]],["self"]]],[11,"from",R[76],E,4,[[],["self"]]],[11,"fmt",R[74],E,1,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",R[75],E,2,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,2,[[["self"],[R[36]]],[R[5]]]]],"p":[[3,R[79]],[3,R[80]],[4,R[81]],[8,R[82]],[3,"Tls"]]};
searchIndex["libtls_sys"]={"doc":E,"i":[[3,R[14],"libtls_sys",E,N,N],[12,"__val",E,E,0,N],[3,R[15],E,E,N,N],[12,"__val",E,E,1,N],[3,R[37],E,E,N,N],[12,R[0],E,E,2,N],[12,"tv_usec",E,E,2,N],[3,R[16],E,E,N,N],[12,R[0],E,E,3,N],[12,"tv_nsec",E,E,3,N],[3,"fd_set",E,E,N,N],[12,"__fds_bits",E,E,4,N],[3,R[17],E,E,N,N],[12,"__readers",E,E,5,N],[12,"__writers",E,E,5,N],[12,"__wrphase_futex",E,E,5,N],[12,"__writers_futex",E,E,5,N],[12,"__pad3",E,E,5,N],[12,"__pad4",E,E,5,N],[12,"__cur_writer",E,E,5,N],[12,"__shared",E,E,5,N],[12,"__rwelision",E,E,5,N],[12,"__pad1",E,E,5,N],[12,"__pad2",E,E,5,N],[12,"__flags",E,E,5,N],[3,R[18],E,E,N,N],[12,"__prev",E,E,6,N],[12,"__next",E,E,6,N],[3,R[19],E,E,N,N],[12,"__lock",E,E,7,N],[12,"__count",E,E,7,N],[12,"__owner",E,E,7,N],[12,"__nusers",E,E,7,N],[12,"__kind",E,E,7,N],[12,"__spins",E,E,7,N],[12,"__elision",E,E,7,N],[12,"__list",E,E,7,N],[3,R[20],E,E,N,N],[12,"__bindgen_anon_1",E,E,8,N],[12,"__bindgen_anon_2",E,E,8,N],[12,"__g_refs",E,E,8,N],[12,"__g_size",E,E,8,N],[12,"__g1_orig_size",E,E,8,N],[12,"__wrefs",E,E,8,N],[12,"__g_signals",E,E,8,N],[3,R[22],E,E,N,N],[12,"__low",E,E,9,N],[12,R[1],E,E,9,N],[3,R[24],E,E,N,N],[12,"__low",E,E,10,N],[12,R[1],E,E,10,N],[3,R[34],E,E,N,N],[12,"__clang_max_align_nonce1",E,E,11,N],[12,"__bindgen_padding_0",E,E,11,N],[12,"__clang_max_align_nonce2",E,E,11,N],[3,"tls",E,E,N,N],[3,R[35],E,E,N,N],[19,R[21],E,E,N,N],[12,"__wseq",E,E,12,N],[12,"__wseq32",E,E,12,N],[19,R[23],E,E,N,N],[12,"__g1_start",E,E,13,N],[12,"__g1_start32",E,E,13,N],[19,R[25],E,E,N,N],[12,R[2],E,E,14,N],[12,R[3],E,E,14,N],[19,R[26],E,E,N,N],[12,R[2],E,E,15,N],[12,R[3],E,E,15,N],[19,R[27],E,E,N,N],[12,R[2],E,E,16,N],[12,R[3],E,E,16,N],[19,R[28],E,E,N,N],[12,R[4],E,E,17,N],[12,R[2],E,E,17,N],[12,R[3],E,E,17,N],[19,R[29],E,E,N,N],[12,R[4],E,E,18,N],[12,R[2],E,E,18,N],[12,R[3],E,E,18,N],[19,R[30],E,E,N,N],[12,R[4],E,E,19,N],[12,R[2],E,E,19,N],[12,R[3],E,E,19,N],[19,R[31],E,E,N,N],[12,R[2],E,E,20,N],[12,R[3],E,E,20,N],[19,R[32],E,E,N,N],[12,R[2],E,E,21,N],[12,R[3],E,E,21,N],[19,R[33],E,E,N,N],[12,R[2],E,E,22,N],[12,R[3],E,E,22,N],[5,"select",E,E,N,N],[5,"pselect",E,E,N,N],[5,"tls_init",E,E,N,N],[5,"tls_config_error",E,E,N,N],[5,"tls_error",E,E,N,N],[5,"tls_config_new",E,E,N,N],[5,"tls_config_free",E,E,N,N],[5,"tls_default_ca_cert_file",E,E,N,N],[5,"tls_config_add_keypair_file",E,E,N,N],[5,"tls_config_add_keypair_mem",E,E,N,N],[5,"tls_config_add_keypair_ocsp_file",E,E,N,N],[5,"tls_config_add_keypair_ocsp_mem",E,E,N,N],[5,"tls_config_set_alpn",E,E,N,N],[5,"tls_config_set_ca_file",E,E,N,N],[5,"tls_config_set_ca_path",E,E,N,N],[5,R[83],E,E,N,N],[5,"tls_config_set_cert_file",E,E,N,N],[5,"tls_config_set_cert_mem",E,E,N,N],[5,"tls_config_set_ciphers",E,E,N,N],[5,"tls_config_set_crl_file",E,E,N,N],[5,"tls_config_set_crl_mem",E,E,N,N],[5,"tls_config_set_dheparams",E,E,N,N],[5,"tls_config_set_ecdhecurve",E,E,N,N],[5,"tls_config_set_ecdhecurves",E,E,N,N],[5,"tls_config_set_key_file",E,E,N,N],[5,"tls_config_set_key_mem",E,E,N,N],[5,"tls_config_set_keypair_file",E,E,N,N],[5,"tls_config_set_keypair_mem",E,E,N,N],[5,"tls_config_set_keypair_ocsp_file",E,E,N,N],[5,"tls_config_set_keypair_ocsp_mem",E,E,N,N],[5,"tls_config_set_ocsp_staple_mem",E,E,N,N],[5,"tls_config_set_ocsp_staple_file",E,E,N,N],[5,"tls_config_set_protocols",E,E,N,N],[5,"tls_config_set_session_fd",E,E,N,N],[5,"tls_config_set_verify_depth",E,E,N,N],[5,"tls_config_prefer_ciphers_client",E,E,N,N],[5,"tls_config_prefer_ciphers_server",E,E,N,N],[5,"tls_config_insecure_noverifycert",E,E,N,N],[5,"tls_config_insecure_noverifyname",E,E,N,N],[5,"tls_config_insecure_noverifytime",E,E,N,N],[5,"tls_config_verify",E,E,N,N],[5,"tls_config_ocsp_require_stapling",E,E,N,N],[5,"tls_config_verify_client",E,E,N,N],[5,"tls_config_verify_client_optional",E,E,N,N],[5,"tls_config_clear_keys",E,E,N,N],[5,"tls_config_parse_protocols",E,E,N,N],[5,"tls_config_set_session_id",E,E,N,N],[5,"tls_config_set_session_lifetime",E,E,N,N],[5,"tls_config_add_ticket_key",E,E,N,N],[5,"tls_client",E,E,N,N],[5,"tls_server",E,E,N,N],[5,"tls_configure",E,E,N,N],[5,"tls_reset",E,E,N,N],[5,"tls_free",E,E,N,N],[5,"tls_accept_fds",E,E,N,N],[5,"tls_accept_socket",E,E,N,N],[5,"tls_accept_cbs",E,E,N,N],[5,"tls_connect",E,E,N,N],[5,"tls_connect_fds",E,E,N,N],[5,"tls_connect_servername",E,E,N,N],[5,"tls_connect_socket",E,E,N,N],[5,"tls_connect_cbs",E,E,N,N],[5,"tls_handshake",E,E,N,N],[5,"tls_read",E,E,N,N],[5,"tls_write",E,E,N,N],[5,"tls_close",E,E,N,N],[5,"tls_peer_cert_provided",E,E,N,N],[5,"tls_peer_cert_contains_name",E,E,N,N],[5,"tls_peer_cert_hash",E,E,N,N],[5,"tls_peer_cert_issuer",E,E,N,N],[5,"tls_peer_cert_subject",E,E,N,N],[5,"tls_peer_cert_notbefore",E,E,N,N],[5,"tls_peer_cert_notafter",E,E,N,N],[5,"tls_peer_cert_chain_pem",E,E,N,N],[5,"tls_conn_alpn_selected",E,E,N,N],[5,"tls_conn_cipher",E,E,N,N],[5,"tls_conn_servername",E,E,N,N],[5,"tls_conn_session_resumed",E,E,N,N],[5,"tls_conn_version",E,E,N,N],[5,"tls_load_file",E,E,N,N],[5,"tls_unload_file",E,E,N,N],[5,"tls_ocsp_process_response",E,E,N,N],[5,"tls_peer_ocsp_cert_status",E,E,N,N],[5,"tls_peer_ocsp_crl_reason",E,E,N,N],[5,"tls_peer_ocsp_next_update",E,E,N,N],[5,"tls_peer_ocsp_response_status",E,E,N,N],[5,"tls_peer_ocsp_result",E,E,N,N],[5,"tls_peer_ocsp_revocation_time",E,E,N,N],[5,"tls_peer_ocsp_this_update",E,E,N,N],[5,"tls_peer_ocsp_url",E,E,N,N],[5,"close",E,E,N,N],[6,"__u_char",E,E,N,N],[6,"__u_short",E,E,N,N],[6,"__u_int",E,E,N,N],[6,"__u_long",E,E,N,N],[6,"__int8_t",E,E,N,N],[6,"__uint8_t",E,E,N,N],[6,"__int16_t",E,E,N,N],[6,"__uint16_t",E,E,N,N],[6,"__int32_t",E,E,N,N],[6,"__uint32_t",E,E,N,N],[6,"__int64_t",E,E,N,N],[6,"__uint64_t",E,E,N,N],[6,"__int_least8_t",E,E,N,N],[6,"__uint_least8_t",E,E,N,N],[6,"__int_least16_t",E,E,N,N],[6,"__uint_least16_t",E,E,N,N],[6,"__int_least32_t",E,E,N,N],[6,"__uint_least32_t",E,E,N,N],[6,"__int_least64_t",E,E,N,N],[6,"__uint_least64_t",E,E,N,N],[6,"__quad_t",E,E,N,N],[6,"__u_quad_t",E,E,N,N],[6,"__intmax_t",E,E,N,N],[6,"__uintmax_t",E,E,N,N],[6,"__dev_t",E,E,N,N],[6,"__uid_t",E,E,N,N],[6,"__gid_t",E,E,N,N],[6,"__ino_t",E,E,N,N],[6,"__ino64_t",E,E,N,N],[6,"__mode_t",E,E,N,N],[6,"__nlink_t",E,E,N,N],[6,"__off_t",E,E,N,N],[6,"__off64_t",E,E,N,N],[6,"__pid_t",E,E,N,N],[6,"__clock_t",E,E,N,N],[6,"__rlim_t",E,E,N,N],[6,"__rlim64_t",E,E,N,N],[6,"__id_t",E,E,N,N],[6,"__time_t",E,E,N,N],[6,"__useconds_t",E,E,N,N],[6,"__suseconds_t",E,E,N,N],[6,"__daddr_t",E,E,N,N],[6,"__key_t",E,E,N,N],[6,"__clockid_t",E,E,N,N],[6,"__timer_t",E,E,N,N],[6,"__blksize_t",E,E,N,N],[6,"__blkcnt_t",E,E,N,N],[6,"__blkcnt64_t",E,E,N,N],[6,"__fsblkcnt_t",E,E,N,N],[6,"__fsblkcnt64_t",E,E,N,N],[6,"__fsfilcnt_t",E,E,N,N],[6,"__fsfilcnt64_t",E,E,N,N],[6,"__fsword_t",E,E,N,N],[6,"__ssize_t",E,E,N,N],[6,"__syscall_slong_t",E,E,N,N],[6,"__syscall_ulong_t",E,E,N,N],[6,"__loff_t",E,E,N,N],[6,"__caddr_t",E,E,N,N],[6,"__intptr_t",E,E,N,N],[6,"__socklen_t",E,E,N,N],[6,"__sig_atomic_t",E,E,N,N],[6,"u_char",E,E,N,N],[6,"u_short",E,E,N,N],[6,"u_int",E,E,N,N],[6,"u_long",E,E,N,N],[6,"quad_t",E,E,N,N],[6,"u_quad_t",E,E,N,N],[6,"fsid_t",E,E,N,N],[6,"loff_t",E,E,N,N],[6,"ino_t",E,E,N,N],[6,"dev_t",E,E,N,N],[6,"gid_t",E,E,N,N],[6,"mode_t",E,E,N,N],[6,"nlink_t",E,E,N,N],[6,"uid_t",E,E,N,N],[6,"off_t",E,E,N,N],[6,"pid_t",E,E,N,N],[6,"id_t",E,E,N,N],[6,"daddr_t",E,E,N,N],[6,"caddr_t",E,E,N,N],[6,"key_t",E,E,N,N],[6,"clock_t",E,E,N,N],[6,"clockid_t",E,E,N,N],[6,"time_t",E,E,N,N],[6,"timer_t",E,E,N,N],[6,"ulong",E,E,N,N],[6,"ushort",E,E,N,N],[6,"uint",E,E,N,N],[6,"u_int8_t",E,E,N,N],[6,"u_int16_t",E,E,N,N],[6,"u_int32_t",E,E,N,N],[6,"u_int64_t",E,E,N,N],[6,"register_t",E,E,N,N],[6,"sigset_t",E,E,N,N],[6,"suseconds_t",E,E,N,N],[6,"__fd_mask",E,E,N,N],[6,"fd_mask",E,E,N,N],[6,"blksize_t",E,E,N,N],[6,"blkcnt_t",E,E,N,N],[6,"fsblkcnt_t",E,E,N,N],[6,"fsfilcnt_t",E,E,N,N],[6,"__pthread_list_t",E,E,N,N],[6,"pthread_t",E,E,N,N],[6,"pthread_key_t",E,E,N,N],[6,"pthread_once_t",E,E,N,N],[6,"pthread_spinlock_t",E,E,N,N],[6,"wchar_t",E,E,N,N],[6,"int_least8_t",E,E,N,N],[6,"int_least16_t",E,E,N,N],[6,"int_least32_t",E,E,N,N],[6,"int_least64_t",E,E,N,N],[6,"uint_least8_t",E,E,N,N],[6,"uint_least16_t",E,E,N,N],[6,"uint_least32_t",E,E,N,N],[6,"uint_least64_t",E,E,N,N],[6,"int_fast8_t",E,E,N,N],[6,"int_fast16_t",E,E,N,N],[6,"int_fast32_t",E,E,N,N],[6,"int_fast64_t",E,E,N,N],[6,"uint_fast8_t",E,E,N,N],[6,"uint_fast16_t",E,E,N,N],[6,"uint_fast32_t",E,E,N,N],[6,"uint_fast64_t",E,E,N,N],[6,"intmax_t",E,E,N,N],[6,"uintmax_t",E,E,N,N],[6,"tls_read_cb",E,E,N,N],[6,"tls_write_cb",E,E,N,N],[17,"_SYS_TYPES_H",E,E,N,N],[17,"_FEATURES_H",E,E,N,N],[17,"_DEFAULT_SOURCE",E,E,N,N],[17,"__USE_ISOC11",E,E,N,N],[17,"__USE_ISOC99",E,E,N,N],[17,"__USE_ISOC95",E,E,N,N],[17,"__USE_POSIX_IMPLICITLY",E,E,N,N],[17,"_POSIX_SOURCE",E,E,N,N],[17,"_POSIX_C_SOURCE",E,E,N,N],[17,"__USE_POSIX",E,E,N,N],[17,"__USE_POSIX2",E,E,N,N],[17,"__USE_POSIX199309",E,E,N,N],[17,"__USE_POSIX199506",E,E,N,N],[17,"__USE_XOPEN2K",E,E,N,N],[17,"__USE_XOPEN2K8",E,E,N,N],[17,"_ATFILE_SOURCE",E,E,N,N],[17,"__USE_MISC",E,E,N,N],[17,"__USE_ATFILE",E,E,N,N],[17,"__USE_FORTIFY_LEVEL",E,E,N,N],[17,"__GLIBC_USE_DEPRECATED_GETS",E,E,N,N],[17,"__GLIBC_USE_DEPRECATED_SCANF",E,E,N,N],[17,"_STDC_PREDEF_H",E,E,N,N],[17,"__STDC_IEC_559__",E,E,N,N],[17,"__STDC_IEC_559_COMPLEX__",E,E,N,N],[17,"__STDC_ISO_10646__",E,E,N,N],[17,"__GNU_LIBRARY__",E,E,N,N],[17,"__GLIBC__",E,E,N,N],[17,"__GLIBC_MINOR__",E,E,N,N],[17,"_SYS_CDEFS_H",E,E,N,N],[17,"__glibc_c99_flexarr_available",E,E,N,N],[17,"__WORDSIZE",E,E,N,N],[17,"__WORDSIZE_TIME64_COMPAT32",E,E,N,N],[17,"__SYSCALL_WORDSIZE",E,E,N,N],[17,"__HAVE_GENERIC_SELECTION",E,E,N,N],[17,"_BITS_TYPES_H",E,E,N,N],[17,"__TIMESIZE",E,E,N,N],[17,"_BITS_TYPESIZES_H",E,E,N,N],[17,"__OFF_T_MATCHES_OFF64_T",E,E,N,N],[17,"__INO_T_MATCHES_INO64_T",E,E,N,N],[17,"__RLIM_T_MATCHES_RLIM64_T",E,E,N,N],[17,"__FD_SETSIZE",E,E,N,N],[17,"_BITS_TIME64_H",E,E,N,N],[17,"__clock_t_defined",E,E,N,N],[17,"__clockid_t_defined",E,E,N,N],[17,"__time_t_defined",E,E,N,N],[17,"__timer_t_defined",E,E,N,N],[17,"_BITS_STDINT_INTN_H",E,E,N,N],[17,"__BIT_TYPES_DEFINED__",E,E,N,N],[17,"_ENDIAN_H",E,E,N,N],[17,"__LITTLE_ENDIAN",E,E,N,N],[17,"__BIG_ENDIAN",E,E,N,N],[17,"__PDP_ENDIAN",E,E,N,N],[17,"__BYTE_ORDER",E,E,N,N],[17,"__FLOAT_WORD_ORDER",E,E,N,N],[17,"LITTLE_ENDIAN",E,E,N,N],[17,"BIG_ENDIAN",E,E,N,N],[17,"PDP_ENDIAN",E,E,N,N],[17,"BYTE_ORDER",E,E,N,N],[17,"_BITS_BYTESWAP_H",E,E,N,N],[17,"_BITS_UINTN_IDENTITY_H",E,E,N,N],[17,"_SYS_SELECT_H",E,E,N,N],[17,"__FD_ZERO_STOS",E,E,N,N],[17,"__sigset_t_defined",E,E,N,N],[17,"__timeval_defined",E,E,N,N],[17,"_STRUCT_TIMESPEC",E,E,N,N],[17,"FD_SETSIZE",E,E,N,N],[17,"_BITS_PTHREADTYPES_COMMON_H",E,E,N,N],[17,"_THREAD_SHARED_TYPES_H",E,E,N,N],[17,"_BITS_PTHREADTYPES_ARCH_H",E,E,N,N],[17,"__SIZEOF_PTHREAD_MUTEX_T",E,E,N,N],[17,"__SIZEOF_PTHREAD_ATTR_T",E,E,N,N],[17,"__SIZEOF_PTHREAD_RWLOCK_T",E,E,N,N],[17,"__SIZEOF_PTHREAD_BARRIER_T",E,E,N,N],[17,"__SIZEOF_PTHREAD_MUTEXATTR_T",E,E,N,N],[17,"__SIZEOF_PTHREAD_COND_T",E,E,N,N],[17,"__SIZEOF_PTHREAD_CONDATTR_T",E,E,N,N],[17,"__SIZEOF_PTHREAD_RWLOCKATTR_T",E,E,N,N],[17,"__SIZEOF_PTHREAD_BARRIERATTR_T",E,E,N,N],[17,"__PTHREAD_MUTEX_LOCK_ELISION",E,E,N,N],[17,"__PTHREAD_MUTEX_NUSERS_AFTER_KIND",E,E,N,N],[17,"__PTHREAD_MUTEX_USE_UNION",E,E,N,N],[17,"__PTHREAD_RWLOCK_INT_FLAGS_SHARED",E,E,N,N],[17,"__PTHREAD_MUTEX_HAVE_PREV",E,E,N,N],[17,"__have_pthread_attr_t",E,E,N,N],[17,"_STDINT_H",E,E,N,N],[17,"__GLIBC_USE_LIB_EXT2",E,E,N,N],[17,"__GLIBC_USE_IEC_60559_BFP_EXT",E,E,N,N],[17,"__GLIBC_USE_IEC_60559_FUNCS_EXT",E,E,N,N],[17,"__GLIBC_USE_IEC_60559_TYPES_EXT",E,E,N,N],[17,"_BITS_WCHAR_H",E,E,N,N],[17,"_BITS_STDINT_UINTN_H",E,E,N,N],[17,"INT8_MIN",E,E,N,N],[17,"INT16_MIN",E,E,N,N],[17,"INT32_MIN",E,E,N,N],[17,"INT8_MAX",E,E,N,N],[17,"INT16_MAX",E,E,N,N],[17,"INT32_MAX",E,E,N,N],[17,"UINT8_MAX",E,E,N,N],[17,"UINT16_MAX",E,E,N,N],[17,"UINT32_MAX",E,E,N,N],[17,"INT_LEAST8_MIN",E,E,N,N],[17,"INT_LEAST16_MIN",E,E,N,N],[17,"INT_LEAST32_MIN",E,E,N,N],[17,"INT_LEAST8_MAX",E,E,N,N],[17,"INT_LEAST16_MAX",E,E,N,N],[17,"INT_LEAST32_MAX",E,E,N,N],[17,"UINT_LEAST8_MAX",E,E,N,N],[17,"UINT_LEAST16_MAX",E,E,N,N],[17,"UINT_LEAST32_MAX",E,E,N,N],[17,"INT_FAST8_MIN",E,E,N,N],[17,"INT_FAST16_MIN",E,E,N,N],[17,"INT_FAST32_MIN",E,E,N,N],[17,"INT_FAST8_MAX",E,E,N,N],[17,"INT_FAST16_MAX",E,E,N,N],[17,"INT_FAST32_MAX",E,E,N,N],[17,"UINT_FAST8_MAX",E,E,N,N],[17,"UINT_FAST16_MAX",E,E,N,N],[17,"UINT_FAST32_MAX",E,E,N,N],[17,"INTPTR_MIN",E,E,N,N],[17,"INTPTR_MAX",E,E,N,N],[17,"UINTPTR_MAX",E,E,N,N],[17,"PTRDIFF_MIN",E,E,N,N],[17,"PTRDIFF_MAX",E,E,N,N],[17,"SIG_ATOMIC_MIN",E,E,N,N],[17,"SIG_ATOMIC_MAX",E,E,N,N],[17,"SIZE_MAX",E,E,N,N],[17,"WINT_MIN",E,E,N,N],[17,"WINT_MAX",E,E,N,N],[17,"TLS_API",E,E,N,N],[17,R[84],E,E,N,N],[17,R[85],E,E,N,N],[17,R[86],E,E,N,N],[17,R[87],E,E,N,N],[17,R[88],E,E,N,N],[17,R[89],E,E,N,N],[17,R[90],E,E,N,N],[17,R[91],E,E,N,N],[17,R[92],E,E,N,N],[17,R[93],E,E,N,N],[17,R[94],E,E,N,N],[17,R[95],E,E,N,N],[17,R[96],E,E,N,N],[17,R[97],E,E,N,N],[17,R[98],E,E,N,N],[17,R[99],E,E,N,N],[17,R[100],E,E,N,N],[17,R[101],E,E,N,N],[17,R[102],E,E,N,N],[17,R[103],E,E,N,N],[17,R[104],E,E,N,N],[17,R[105],E,E,N,N],[17,R[106],E,E,N,N],[17,R[107],E,E,N,N],[17,R[108],E,E,N,N],[17,R[109],E,E,N,N],[17,R[110],E,E,N,N],[17,R[111],E,E,N,N],[17,R[112],E,E,N,N],[11,R[6],E,E,0,[[["self"]],[T]]],[11,R[7],E,E,0,[[["self"],[T]]]],[11,"into",E,E,0,[[],[U]]],[11,"from",E,E,0,[[[T]],[T]]],[11,R[8],E,E,0,[[[U]],[R[5]]]],[11,R[9],E,E,0,[[],[R[5]]]],[11,R[10],E,E,0,[[["self"]],[T]]],[11,R[12],E,E,0,[[["self"]],[T]]],[11,R[11],E,E,0,[[["self"]],[R[13]]]],[11,R[6],E,E,1,[[["self"]],[T]]],[11,R[7],E,E,1,[[["self"],[T]]]],[11,"into",E,E,1,[[],[U]]],[11,"from",E,E,1,[[[T]],[T]]],[11,R[8],E,E,1,[[[U]],[R[5]]]],[11,R[9],E,E,1,[[],[R[5]]]],[11,R[10],E,E,1,[[["self"]],[T]]],[11,R[12],E,E,1,[[["self"]],[T]]],[11,R[11],E,E,1,[[["self"]],[R[13]]]],[11,R[6],E,E,2,[[["self"]],[T]]],[11,R[7],E,E,2,[[["self"],[T]]]],[11,"into",E,E,2,[[],[U]]],[11,"from",E,E,2,[[[T]],[T]]],[11,R[8],E,E,2,[[[U]],[R[5]]]],[11,R[9],E,E,2,[[],[R[5]]]],[11,R[10],E,E,2,[[["self"]],[T]]],[11,R[12],E,E,2,[[["self"]],[T]]],[11,R[11],E,E,2,[[["self"]],[R[13]]]],[11,R[6],E,E,3,[[["self"]],[T]]],[11,R[7],E,E,3,[[["self"],[T]]]],[11,"into",E,E,3,[[],[U]]],[11,"from",E,E,3,[[[T]],[T]]],[11,R[8],E,E,3,[[[U]],[R[5]]]],[11,R[9],E,E,3,[[],[R[5]]]],[11,R[10],E,E,3,[[["self"]],[T]]],[11,R[12],E,E,3,[[["self"]],[T]]],[11,R[11],E,E,3,[[["self"]],[R[13]]]],[11,R[6],E,E,4,[[["self"]],[T]]],[11,R[7],E,E,4,[[["self"],[T]]]],[11,"into",E,E,4,[[],[U]]],[11,"from",E,E,4,[[[T]],[T]]],[11,R[8],E,E,4,[[[U]],[R[5]]]],[11,R[9],E,E,4,[[],[R[5]]]],[11,R[10],E,E,4,[[["self"]],[T]]],[11,R[12],E,E,4,[[["self"]],[T]]],[11,R[11],E,E,4,[[["self"]],[R[13]]]],[11,R[6],E,E,5,[[["self"]],[T]]],[11,R[7],E,E,5,[[["self"],[T]]]],[11,"into",E,E,5,[[],[U]]],[11,"from",E,E,5,[[[T]],[T]]],[11,R[8],E,E,5,[[[U]],[R[5]]]],[11,R[9],E,E,5,[[],[R[5]]]],[11,R[10],E,E,5,[[["self"]],[T]]],[11,R[12],E,E,5,[[["self"]],[T]]],[11,R[11],E,E,5,[[["self"]],[R[13]]]],[11,R[6],E,E,6,[[["self"]],[T]]],[11,R[7],E,E,6,[[["self"],[T]]]],[11,"into",E,E,6,[[],[U]]],[11,"from",E,E,6,[[[T]],[T]]],[11,R[8],E,E,6,[[[U]],[R[5]]]],[11,R[9],E,E,6,[[],[R[5]]]],[11,R[10],E,E,6,[[["self"]],[T]]],[11,R[12],E,E,6,[[["self"]],[T]]],[11,R[11],E,E,6,[[["self"]],[R[13]]]],[11,R[6],E,E,7,[[["self"]],[T]]],[11,R[7],E,E,7,[[["self"],[T]]]],[11,"into",E,E,7,[[],[U]]],[11,"from",E,E,7,[[[T]],[T]]],[11,R[8],E,E,7,[[[U]],[R[5]]]],[11,R[9],E,E,7,[[],[R[5]]]],[11,R[10],E,E,7,[[["self"]],[T]]],[11,R[12],E,E,7,[[["self"]],[T]]],[11,R[11],E,E,7,[[["self"]],[R[13]]]],[11,R[6],E,E,8,[[["self"]],[T]]],[11,R[7],E,E,8,[[["self"],[T]]]],[11,"into",E,E,8,[[],[U]]],[11,"from",E,E,8,[[[T]],[T]]],[11,R[8],E,E,8,[[[U]],[R[5]]]],[11,R[9],E,E,8,[[],[R[5]]]],[11,R[10],E,E,8,[[["self"]],[T]]],[11,R[12],E,E,8,[[["self"]],[T]]],[11,R[11],E,E,8,[[["self"]],[R[13]]]],[11,R[6],E,E,9,[[["self"]],[T]]],[11,R[7],E,E,9,[[["self"],[T]]]],[11,"into",E,E,9,[[],[U]]],[11,"from",E,E,9,[[[T]],[T]]],[11,R[8],E,E,9,[[[U]],[R[5]]]],[11,R[9],E,E,9,[[],[R[5]]]],[11,R[10],E,E,9,[[["self"]],[T]]],[11,R[12],E,E,9,[[["self"]],[T]]],[11,R[11],E,E,9,[[["self"]],[R[13]]]],[11,R[6],E,E,10,[[["self"]],[T]]],[11,R[7],E,E,10,[[["self"],[T]]]],[11,"into",E,E,10,[[],[U]]],[11,"from",E,E,10,[[[T]],[T]]],[11,R[8],E,E,10,[[[U]],[R[5]]]],[11,R[9],E,E,10,[[],[R[5]]]],[11,R[10],E,E,10,[[["self"]],[T]]],[11,R[12],E,E,10,[[["self"]],[T]]],[11,R[11],E,E,10,[[["self"]],[R[13]]]],[11,R[6],E,E,11,[[["self"]],[T]]],[11,R[7],E,E,11,[[["self"],[T]]]],[11,"into",E,E,11,[[],[U]]],[11,"from",E,E,11,[[[T]],[T]]],[11,R[8],E,E,11,[[[U]],[R[5]]]],[11,R[9],E,E,11,[[],[R[5]]]],[11,R[10],E,E,11,[[["self"]],[T]]],[11,R[12],E,E,11,[[["self"]],[T]]],[11,R[11],E,E,11,[[["self"]],[R[13]]]],[11,R[6],E,E,23,[[["self"]],[T]]],[11,R[7],E,E,23,[[["self"],[T]]]],[11,"into",E,E,23,[[],[U]]],[11,"from",E,E,23,[[[T]],[T]]],[11,R[8],E,E,23,[[[U]],[R[5]]]],[11,R[9],E,E,23,[[],[R[5]]]],[11,R[10],E,E,23,[[["self"]],[T]]],[11,R[12],E,E,23,[[["self"]],[T]]],[11,R[11],E,E,23,[[["self"]],[R[13]]]],[11,R[6],E,E,24,[[["self"]],[T]]],[11,R[7],E,E,24,[[["self"],[T]]]],[11,"into",E,E,24,[[],[U]]],[11,"from",E,E,24,[[[T]],[T]]],[11,R[8],E,E,24,[[[U]],[R[5]]]],[11,R[9],E,E,24,[[],[R[5]]]],[11,R[10],E,E,24,[[["self"]],[T]]],[11,R[12],E,E,24,[[["self"]],[T]]],[11,R[11],E,E,24,[[["self"]],[R[13]]]],[11,R[6],E,E,12,[[["self"]],[T]]],[11,R[7],E,E,12,[[["self"],[T]]]],[11,"into",E,E,12,[[],[U]]],[11,"from",E,E,12,[[[T]],[T]]],[11,R[8],E,E,12,[[[U]],[R[5]]]],[11,R[9],E,E,12,[[],[R[5]]]],[11,R[10],E,E,12,[[["self"]],[T]]],[11,R[12],E,E,12,[[["self"]],[T]]],[11,R[11],E,E,12,[[["self"]],[R[13]]]],[11,R[6],E,E,13,[[["self"]],[T]]],[11,R[7],E,E,13,[[["self"],[T]]]],[11,"into",E,E,13,[[],[U]]],[11,"from",E,E,13,[[[T]],[T]]],[11,R[8],E,E,13,[[[U]],[R[5]]]],[11,R[9],E,E,13,[[],[R[5]]]],[11,R[10],E,E,13,[[["self"]],[T]]],[11,R[12],E,E,13,[[["self"]],[T]]],[11,R[11],E,E,13,[[["self"]],[R[13]]]],[11,R[6],E,E,14,[[["self"]],[T]]],[11,R[7],E,E,14,[[["self"],[T]]]],[11,"into",E,E,14,[[],[U]]],[11,"from",E,E,14,[[[T]],[T]]],[11,R[8],E,E,14,[[[U]],[R[5]]]],[11,R[9],E,E,14,[[],[R[5]]]],[11,R[10],E,E,14,[[["self"]],[T]]],[11,R[12],E,E,14,[[["self"]],[T]]],[11,R[11],E,E,14,[[["self"]],[R[13]]]],[11,R[6],E,E,15,[[["self"]],[T]]],[11,R[7],E,E,15,[[["self"],[T]]]],[11,"into",E,E,15,[[],[U]]],[11,"from",E,E,15,[[[T]],[T]]],[11,R[8],E,E,15,[[[U]],[R[5]]]],[11,R[9],E,E,15,[[],[R[5]]]],[11,R[10],E,E,15,[[["self"]],[T]]],[11,R[12],E,E,15,[[["self"]],[T]]],[11,R[11],E,E,15,[[["self"]],[R[13]]]],[11,R[6],E,E,16,[[["self"]],[T]]],[11,R[7],E,E,16,[[["self"],[T]]]],[11,"into",E,E,16,[[],[U]]],[11,"from",E,E,16,[[[T]],[T]]],[11,R[8],E,E,16,[[[U]],[R[5]]]],[11,R[9],E,E,16,[[],[R[5]]]],[11,R[10],E,E,16,[[["self"]],[T]]],[11,R[12],E,E,16,[[["self"]],[T]]],[11,R[11],E,E,16,[[["self"]],[R[13]]]],[11,R[6],E,E,17,[[["self"]],[T]]],[11,R[7],E,E,17,[[["self"],[T]]]],[11,"into",E,E,17,[[],[U]]],[11,"from",E,E,17,[[[T]],[T]]],[11,R[8],E,E,17,[[[U]],[R[5]]]],[11,R[9],E,E,17,[[],[R[5]]]],[11,R[10],E,E,17,[[["self"]],[T]]],[11,R[12],E,E,17,[[["self"]],[T]]],[11,R[11],E,E,17,[[["self"]],[R[13]]]],[11,R[6],E,E,18,[[["self"]],[T]]],[11,R[7],E,E,18,[[["self"],[T]]]],[11,"into",E,E,18,[[],[U]]],[11,"from",E,E,18,[[[T]],[T]]],[11,R[8],E,E,18,[[[U]],[R[5]]]],[11,R[9],E,E,18,[[],[R[5]]]],[11,R[10],E,E,18,[[["self"]],[T]]],[11,R[12],E,E,18,[[["self"]],[T]]],[11,R[11],E,E,18,[[["self"]],[R[13]]]],[11,R[6],E,E,19,[[["self"]],[T]]],[11,R[7],E,E,19,[[["self"],[T]]]],[11,"into",E,E,19,[[],[U]]],[11,"from",E,E,19,[[[T]],[T]]],[11,R[8],E,E,19,[[[U]],[R[5]]]],[11,R[9],E,E,19,[[],[R[5]]]],[11,R[10],E,E,19,[[["self"]],[T]]],[11,R[12],E,E,19,[[["self"]],[T]]],[11,R[11],E,E,19,[[["self"]],[R[13]]]],[11,R[6],E,E,20,[[["self"]],[T]]],[11,R[7],E,E,20,[[["self"],[T]]]],[11,"into",E,E,20,[[],[U]]],[11,"from",E,E,20,[[[T]],[T]]],[11,R[8],E,E,20,[[[U]],[R[5]]]],[11,R[9],E,E,20,[[],[R[5]]]],[11,R[10],E,E,20,[[["self"]],[T]]],[11,R[12],E,E,20,[[["self"]],[T]]],[11,R[11],E,E,20,[[["self"]],[R[13]]]],[11,R[6],E,E,21,[[["self"]],[T]]],[11,R[7],E,E,21,[[["self"],[T]]]],[11,"into",E,E,21,[[],[U]]],[11,"from",E,E,21,[[[T]],[T]]],[11,R[8],E,E,21,[[[U]],[R[5]]]],[11,R[9],E,E,21,[[],[R[5]]]],[11,R[10],E,E,21,[[["self"]],[T]]],[11,R[12],E,E,21,[[["self"]],[T]]],[11,R[11],E,E,21,[[["self"]],[R[13]]]],[11,R[6],E,E,22,[[["self"]],[T]]],[11,R[7],E,E,22,[[["self"],[T]]]],[11,"into",E,E,22,[[],[U]]],[11,"from",E,E,22,[[[T]],[T]]],[11,R[8],E,E,22,[[[U]],[R[5]]]],[11,R[9],E,E,22,[[],[R[5]]]],[11,R[10],E,E,22,[[["self"]],[T]]],[11,R[12],E,E,22,[[["self"]],[T]]],[11,R[11],E,E,22,[[["self"]],[R[13]]]],[11,"clone",E,E,0,[[["self"]],[R[14]]]],[11,"clone",E,E,1,[[["self"]],[R[15]]]],[11,"clone",E,E,2,[[["self"]],[R[37]]]],[11,"clone",E,E,3,[[["self"]],[R[16]]]],[11,"clone",E,E,4,[[["self"]],["fd_set"]]],[11,"clone",E,E,5,[[["self"]],[R[17]]]],[11,"clone",E,E,6,[[["self"]],[R[18]]]],[11,"clone",E,E,7,[[["self"]],[R[19]]]],[11,"clone",E,E,8,[[["self"]],[R[20]]]],[11,"clone",E,E,12,[[["self"]],[R[21]]]],[11,"clone",E,E,9,[[["self"]],[R[22]]]],[11,"clone",E,E,13,[[["self"]],[R[23]]]],[11,"clone",E,E,10,[[["self"]],[R[24]]]],[11,"clone",E,E,14,[[["self"]],[R[25]]]],[11,"clone",E,E,15,[[["self"]],[R[26]]]],[11,"clone",E,E,16,[[["self"]],[R[27]]]],[11,"clone",E,E,17,[[["self"]],[R[28]]]],[11,"clone",E,E,18,[[["self"]],[R[29]]]],[11,"clone",E,E,19,[[["self"]],[R[30]]]],[11,"clone",E,E,20,[[["self"]],[R[31]]]],[11,"clone",E,E,21,[[["self"]],[R[32]]]],[11,"clone",E,E,22,[[["self"]],[R[33]]]],[11,"clone",E,E,11,[[["self"]],[R[34]]]],[11,"clone",E,E,23,[[["self"]],["tls"]]],[11,"clone",E,E,24,[[["self"]],[R[35]]]],[11,"fmt",E,E,0,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,1,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,2,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,3,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,4,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,5,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,6,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,7,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,9,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,10,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,11,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,23,[[["self"],[R[36]]],[R[5]]]],[11,"fmt",E,E,24,[[["self"],[R[36]]],[R[5]]]]],"p":[[3,R[14]],[3,R[15]],[3,R[37]],[3,R[16]],[3,"fd_set"],[3,R[17]],[3,R[18]],[3,R[19]],[3,R[20]],[3,R[22]],[3,R[24]],[3,R[34]],[19,R[21]],[19,R[23]],[19,R[25]],[19,R[26]],[19,R[27]],[19,R[28]],[19,R[29]],[19,R[30]],[19,R[31]],[19,R[32]],[19,R[33]],[3,"tls"],[3,R[35]]]};
initSearch(searchIndex);addSearchOptions(searchIndex);