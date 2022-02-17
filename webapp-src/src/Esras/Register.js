import React, { Component } from 'react';

import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';

class Register extends Component {
  constructor(props) {
    super(props);

    let redirectUriEsras = window.location.href.substring(0, window.location.href.lastIndexOf('/')) + "/api/client/redirect";
    this.state = {
      client: props.client,
      redirectUriEsras: redirectUriEsras,
      redirectUri: "",
      allowAddRedirectUri: false,
      pubKey: props.client.jwks?JSON.stringify(props.client.jwks):"",
      pubKeyValid: true
    };

    this.verifyRegistration = this.verifyRegistration.bind(this);
    this.changeText = this.changeText.bind(this);
    this.changeRedirectUri = this.changeRedirectUri.bind(this);
    this.changePubkey = this.changePubkey.bind(this);
    this.addRedirectUri = this.addRedirectUri.bind(this);
    this.deleteRedirectUri = this.deleteRedirectUri.bind(this);
    this.toggleClientConfidential = this.toggleClientConfidential.bind(this);
    this.changeAuthMethod = this.changeAuthMethod.bind(this);
    this.setPubKeyValid = this.setPubKeyValid.bind(this);
    this.toggleGrantType = this.toggleGrantType.bind(this);
  }

  static getDerivedStateFromProps(props, state) {
    return props;
  }

  changeText(e, property) {
    let client = this.state.client;
    client[property] = e.target.value;
    this.setState({client: client});
  }

  changeRedirectUri(e) {
    this.setState({redirectUri: e.target.value}, () => {
      this.verifyRedirectUri();
    });
  }

  changePubkey(e) {
    let client = this.state.client;
    let pubKey = this.state.pubKey;
    try {
      pubKey = JSON.parse(e.target.value);
    } catch (e) {
      pubKey = false;
    }
    if (pubKey && client.token_endpoint_auth_method === "private_key_jwt") {
      client.jwks = pubKey;
    } else {
      delete (client.jwks);
    }
    this.setState({client: client, pubKey: e.target.value}, () => {
      this.setPubKeyValid();
    });
  }

  verifyRedirectUri() {
    let redirectUriCase = this.state.redirectUri.toLowerCase();
    let domain = window.location.href.split("/")[1].split(".");

    this.setState({allowAddRedirectUri: (redirectUriCase.startsWith("http://localhost:") || redirectUriCase.startsWith("https://localhost:") ||
      redirectUriCase.startsWith("http://localhost/") || redirectUriCase.startsWith("https://localhost/") ||
    ((redirectUriCase.startsWith("http://") || redirectUriCase.startsWith("https://")) && domain[domain.length-1] === "local"))});
  }

  addRedirectUri() {
    let client = this.state.client;
    client.redirect_uris.push(this.state.redirectUri);
    this.setState({client: client, redirectUri: "", allowAddRedirectUri: false});
  }

  deleteRedirectUri(e, index) {
    e.preventDefault();
    let client = this.state.client;
    client.redirect_uris.splice(index, 1);
    this.setState({client: client});
  }

  toggleClientConfidential() {
    let client = this.state.client;
    client.client_confidential = !client.client_confidential;
    this.setState({client: client});
  }

  changeAuthMethod(e) {
    let client = this.state.client;
    client.token_endpoint_auth_method = e.target.value;
    this.setState({client: client}, () => {
      this.setPubKeyValid();
    });
  }

  setPubKeyValid() {
    let client = this.state.client;
    let pubKeyValid = true;
    if (client.token_endpoint_auth_method === "private_key_jwt") {
      if (!client.jwks || !Array.isArray(client.jwks.keys) || !client.jwks.keys.length) {
        pubKeyValid = false;
      }
    }
    this.setState({pubKeyValid: pubKeyValid});
  }

  toggleGrantType(e, type) {
    let client = this.state.client;
    if (client.grant_types.indexOf(type) !== -1) {
      client.grant_types.splice(client.grant_types.indexOf(type), 1);
    } else {
      client.grant_types.push(type);
    }
    this.setState({client: client});
  }

  toggleResponseType(e, type) {
    let client = this.state.client;
    if (client.response_types.indexOf(type) !== -1) {
      client.response_types.splice(client.response_types.indexOf(type), 1);
    } else {
      client.response_types.push(type);
    }
    this.setState({client: client});
  }

  verifyRegistration(e) {
    e.preventDefault();
    if (this.state.client.token_endpoint_auth_method !== "private_key_jwt" || this.state.client.jwks) {
      if (!this.state.client.client_id) {
        apiManager.request("client", "POST", this.state.client)
        .then(() => {
          messageDispatcher.sendMessage("App", {action: 'nav', target: "reload"});
        })
        .fail(() => {
          messageDispatcher.sendMessage("Notification", {type: "success", message: i18next.t("register_client_error")});
        });
      } else {
        apiManager.request("client/" + this.state.client.client_id, "PUT", this.state.client)
        .then(() => {
          messageDispatcher.sendMessage("App", {action: 'nav', target: "reload"});
        })
        .fail(() => {
          messageDispatcher.sendMessage("Notification", {type: "success", message: i18next.t("register_client_error")});
        });
      }
    } else {
      messageDispatcher.sendMessage("Notification", {type: "success", message: i18next.t("register_client_jwks_required")});
    }
  }

  cancelRegistration() {
    messageDispatcher.sendMessage("App", {action: 'nav', target: "list"});
  }

	render() {
    let redirect_uris = [], errorJwks;
    this.state.client.redirect_uris.forEach((redirect_uri, index) => {
      if (!index) {
        redirect_uris.push(<span key={index} className="badge bg-primary elt-right">{redirect_uri}</span>)
      } else {
        redirect_uris.push(<a href="#"
                              onClick={(e) => this.deleteRedirectUri(e, index)}
                              key={index}>
                             <span className="badge bg-primary elt-right">
                              {redirect_uri}
                              <span className="badge bg-secondary elt-right">
                                <i className="fa fa-times"></i>
                              </span>
                            </span>
                          </a>);
      }
    });
    if (!this.state.pubKeyValid) {
      errorJwks = <div className="text-danger">
        {i18next.t("register_client_jwks_required")}
      </div>;
    }
    return (
      <div>
        <h2>
          {i18next.t("register_client")}
        </h2>
          <hr/>
        <form onSubmit={(e) => this.verifyRegistration(e)}>
          <div className="form-group">
            <label htmlFor="displayName">{i18next.t("register_client_name")}</label>
            <input type="text" className="form-control" id="displayName" value={this.state.client.name} onChange={(e) => this.changeText(e, 'name')}/>
            <small id="displayNameHelp" className="form-text text-muted">{i18next.t("register_client_name_help")}</small>
          </div>
          <hr/>
          <div className="form-group">
            <label htmlFor="redirectUris">{i18next.t("register_client_redirect_uris")}</label>{redirect_uris}
            <div className="input-group mb-3">
              <input type="text" className="form-control" id="redirectUris" value={this.state.redirectUri} onChange={(e) => this.changeRedirectUri(e)}/>
              <div className="input-group-append">
                <button className="btn btn-outline-secondary" type="button" id="button-addon2" disabled={!this.state.allowAddRedirectUri} onClick={this.addRedirectUri}>
                  <i className="fa fa-plus" aria-hidden="true"></i>
                </button>
              </div>
            </div>
            <small id="redirectUrisHelp" className="form-text text-muted">{i18next.t("register_client_redirect_uris_help", {redirectUriEsras: this.state.redirectUriEsras, 'interpolation': {'escapeValue': false}})}</small>
          </div>
          <hr/>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="client_confidential" checked={this.state.client.client_confidential} onChange={this.toggleClientConfidential}/>
            <label className="form-check-label" htmlFor="client_confidential">{i18next.t("register_client_confidential")}</label>
          </div>
          <hr/>
          <div className="form-group">
            <label htmlFor="authMethod">{i18next.t("register_client_auth_method")}</label>
            <select className="form-control" id="authMethod" value={this.state.client.token_endpoint_auth_method} onChange={this.changeAuthMethod} disabled={!this.state.client.client_confidential}>
              <option>client_secret_post</option>
              <option>client_secret_basic</option>
              <option>client_secret_jwt</option>
              <option>private_key_jwt</option>
            </select>
            <small id="authMethodHelp" className="form-text text-muted">{i18next.t("register_client_auth_method_help")}</small>
          </div>
          <hr/>
          <div className="form-group">
            <label htmlFor="grantTypes">{i18next.t("register_client_grant_types")}</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="authorization_code" checked={this.state.client.grant_types.indexOf('authorization_code')>-1} onChange={(e) => this.toggleGrantType(e, 'authorization_code')}/>
            <label className="form-check-label" htmlFor="authorization_code">authorization_code</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="implicit" checked={this.state.client.grant_types.indexOf('implicit')>-1} onChange={(e) => this.toggleGrantType(e, 'implicit')}/>
            <label className="form-check-label" htmlFor="implicit">implicit</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="client_credentials" checked={this.state.client.grant_types.indexOf('client_credentials')>-1} onChange={(e) => this.toggleGrantType(e, 'client_credentials')}/>
            <label className="form-check-label" htmlFor="client_credentials">client_credentials</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="refresh_token" checked={this.state.client.grant_types.indexOf('refresh_token')>-1} onChange={(e) => this.toggleGrantType(e, 'refresh_token')}/>
            <label className="form-check-label" htmlFor="refresh_token">refresh_token</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="delete_token" checked={this.state.client.grant_types.indexOf('delete_token')>-1} onChange={(e) => this.toggleGrantType(e, 'delete_token')}/>
            <label className="form-check-label" htmlFor="delete_token">delete_token</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="device_authorization" checked={this.state.client.grant_types.indexOf('device_authorization')>-1} onChange={(e) => this.toggleGrantType(e, 'device_authorization')}/>
            <label className="form-check-label" htmlFor="device_authorization">device_authorization</label>
          </div>
          <small id="grantTypesHelp" className="form-text text-muted">{i18next.t("register_client_grant_types_help")}</small>
          <hr/>
          <div className="form-group">
            <label htmlFor="grantTypes">{i18next.t("register_client_response_types")}</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="code" checked={this.state.client.response_types.indexOf('code')>-1} onChange={(e) => this.toggleResponseType(e, 'code')}/>
            <label className="form-check-label" htmlFor="code">code</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="token" checked={this.state.client.response_types.indexOf('token')>-1} onChange={(e) => this.toggleResponseType(e, 'token')}/>
            <label className="form-check-label" htmlFor="token">token</label>
          </div>
          <div className="form-group form-check">
            <input type="checkbox" className="form-check-input" id="id_token" checked={this.state.client.response_types.indexOf('id_token')>-1} onChange={(e) => this.toggleResponseType(e, 'id_token')}/>
            <label className="form-check-label" htmlFor="id_token">id_token</label>
          </div>
          <hr/>
          <div className="form-check">
            <label htmlFor="client_jwks">{i18next.t("register_client_jwks")}</label>
            <textarea className="form-control" id="client_jwks" placeholder="{  keys: [  {  kty:[...]" value={this.state.pubKey} onChange={(e) => this.changePubkey(e)}/>
            <small id="jwksHelp" className="form-text text-muted">{i18next.t("register_client_jwks_help")}</small>
            {errorJwks}
          </div>
          <hr/>
          <div className="form-group">
            <button type="submit" className="btn btn-primary elt-left" onClick={(e) => this.verifyRegistration(e)} disabled={!this.state.pubKeyValid}>{i18next.t("submit")}</button>
            <button type="button" className="btn btn-primary" onClick={this.cancelRegistration}>{i18next.t("cancel")}</button>
          </div>
        </form>
      </div>
    );
	}
}

export default Register;
