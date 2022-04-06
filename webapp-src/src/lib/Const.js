class Const {

	constructor() {

    this.responseType = {
      none:               0x00000000,
      code:               0x00000001,
      token:              0x00000010,
      id_token:           0x00000100
    };

    this.grantType = {
      code:               0x00000001,
      password:           0x00001000,
      client_credentials: 0x00010000,
      refresh_token:      0x00100000,
      device_code:        0x01000000,
      ciba:               0x10000000
    };

    this.authMethod = {
      Get:               0x00000001,
      Post:              0x00000010,
      JwtSignSecret:     0x00000100,
      JwtSignPrivkey:    0x00001000,
      JwtEncryptSecret:  0x00010000,
      JwtEncryptPubkey:  0x00100000
    };

    this.tokenMethod = {
      None:             0x00000000,
      SecretBasic:      0x00000001,
      SecretPost:       0x00000010,
      TlsCertificate:   0x00000100,
      JwtSignSecret:    0x00001000,
      JwtSignPrivkey:   0x00010000,
      JwtEncryptSecret: 0x00100000,
      JwtEncryptPubkey: 0x01000000
    }
    
    this.cibaLoginHintMethod = {
      JSON:             0,
      JWT:              1,
      id_token:         2
    };
  }
}

let constant = new Const();

export default constant;
