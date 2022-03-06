import React, { Component } from 'react';

import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';
import constant from '../lib/Const';
import routage from '../lib/Routage';

import Message from './Message';

function getQueryParams(qs) {
  qs = qs.split('+').join(' ');

  var params = {},
    tokens,
    re = /[?&]?([^=]+)=([^&]*)/g;

  while (tokens = re.exec(qs)) {
    params[decodeURIComponent(tokens[1])] = decodeURIComponent(tokens[2]);
  }

  return params;
}

class Exec extends Component {
  constructor(props) {
    super(props);

    this.state = {
      client: props.client,
      oidcConfig: props.oidcConfig,
      menu: props.menu||"auth",
      session: {
        response_type: constant.responseType.code,
        scope: "openid",
        state: "",
        nonce: "",
        auth_method: constant.authMethod.Get,
        token_method: constant.tokenMethod.SecretBasic,
        client_jwks: {keys: []},
        client_sign_alg: ""
      },
      showMessage: false,
      message: {
        title: false,
        message: false
      },
      timeout: false,
      authMethod: constant.authMethod.Get,
      authMethodParams: 0,
      client_jwks: "{\"keys\": []}",
      jwksValid: true,
      clientKid: [],
      userinfoGetJwt: false,
      token_target: "access_token",
      introspection: {}
    };
    
    this.getSession = this.getSession.bind(this);
    this.saveSession = this.saveSession.bind(this);
    this.changeScope = this.changeScope.bind(this);
    this.selectScope = this.selectScope.bind(this);
    this.changeParam = this.changeParam.bind(this);
    this.generateParam = this.generateParam.bind(this);
    this.selectResponseType = this.selectResponseType.bind(this);
    this.selectAuthMethod = this.selectAuthMethod.bind(this);
    this.selectAuthMethodParams = this.selectAuthMethodParams.bind(this);
    this.changeClientJwks = this.changeClientJwks.bind(this);
    this.selectClientKid = this.selectClientKid.bind(this);
    this.showHelp = this.showHelp.bind(this);
    this.closeHelp = this.closeHelp.bind(this);
    this.runAuth = this.runAuth.bind(this);
    this.runToken = this.runToken.bind(this);
    this.runUserinfo = this.runUserinfo.bind(this);
    this.changeUserinfoGetJwt = this.changeUserinfoGetJwt.bind(this);
    this.selectTokenTarget = this.selectTokenTarget.bind(this);
    this.selectPkceMethod = this.selectPkceMethod.bind(this);
    
    this.getSession();
  }
  
  getSession() {
    return apiManager.request("exec/session/" + this.state.client.client_id)
    .then((res) => {
      let authMethod = res.auth_method & ~(constant.authMethod.JwtSignSecret|constant.authMethod.JwtSignPrivkey|constant.authMethod.JwtEncryptSecret|constant.authMethod.JwtEncryptPubkey);
      let authMethodParams = res.auth_method & ~(constant.authMethod.Get|constant.authMethod.Post);
      this.setState({session: res, authMethod: authMethod, authMethodParams: authMethodParams, client_jwks: JSON.stringify(res.client_jwks)});
    })
    .fail((err) => {
      if (err.status === 404) {
        apiManager.request("exec/session/" + this.state.client.client_id, "PUT", this.state.session)
        .then((res) => {
          this.generateParam('state');
        })
        .fail((err) => {
          messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_session_error")});
        });
      } else {
        messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_session_error")});
      }
    });
  }
  
  saveSession(timeout) {
    if (timeout) {
      if (this.state.timeout) {
        clearTimeout(this.state.timeout);
      }
      return this.setState({
        timeout: setTimeout(() => {
          return apiManager.request("exec/session/" + this.state.client.client_id, "PUT", this.state.session)
          .fail((err) => {
            messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_session_error")});
          });
        }, 1000)
      });
    } else {
      return apiManager.request("exec/session/" + this.state.client.client_id, "PUT", this.state.session)
      .fail((err) => {
        messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_session_error")});
      });
    }
  }
  
  changeScope(e) {
    let session = this.state.session;
    session.scope = e.target.value;
    this.setState({session: session}, () => {
      this.saveSession(true);
    });
  }
  
  changeParam(e, param) {
    let session = this.state.session;
    session[param] = e.target.value;
    this.setState({session: session}, () => {
      this.saveSession(true);
    });
  }

  generateParam(param) {
    return apiManager.request("exec/generate/" + this.state.client.client_id + "/" + param, "PUT")
    .then((res) => {
      apiManager.request("exec/session/" + this.state.client.client_id)
      .then((res) => {
        this.setState({session: res});
      })
      .fail(() => {
        messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_session_error")});
      });
    })
    .fail(() => {
      messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_session_error")});
    });
  }

  selectScope(e) {
    let session = this.state.session;
    session.scope += (" " + e.target.value);
    this.setState({session: session}, () => {
      this.saveSession(false);
    });
  }
  
  selectResponseType(e) {
    let session = this.state.session;
    session.response_type = parseInt(e.target.value);
    this.setState({session: session}, () => {
      this.saveSession(false);
    });
  }
  
  selectAuthMethod(e) {
    let session = this.state.session;
    let authMethod = parseInt(e.target.value);
    session.auth_method = authMethod | this.state.authMethodParams;
    this.setState({session: session, authMethod: authMethod}, () => {
      this.saveSession(false);
    });
  }
  
  selectAuthMethodParams(e) {
    let session = this.state.session;
    let authMethodParams = parseInt(e.target.value);
    session.auth_method = authMethodParams | this.state.authMethod;
    this.setState({session: session, authMethodParams: authMethodParams}, () => {
      this.saveSession(false);
    });
  }
  
  selectPkceMethod(e) {
    let session = this.state.session;
    let pkce_method = parseInt(e.target.value);
    session.pkce_method = pkce_method;
    this.setState({session: session}, () => {
      this.saveSession(false);
    });
  }

  changeClientJwks(e) {
    let jwksValid = true, parsedJwks = false, session = this.state.session;
    try {
      parsedJwks = JSON.parse(e.target.value);
    } catch(err) {
      jwksValid = false;
    }
    if (jwksValid) {
      if (!(parsedJwks instanceof Object) ||
          !Array.isArray(parsedJwks.keys)) {
        jwksValid = false;
      } else {
        parsedJwks.keys.forEach(jwk => {
          if (!(jwk instanceof Object)) {
            jwksValid = false;
          }
        });
      }
    }
    if (jwksValid) {
      session.client_jwks = parsedJwks;
      if (parsedJwks.keys[0] && parsedJwks.keys[0].kid) {
        session.client_kid = parsedJwks.keys[0].kid;
      };
    }
    this.setState({jwksValid: jwksValid, client_jwks: e.target.value, session: session}, () => {
      this.saveSession(true);
    });
  }
  
  selectClientKid(e) {
    let session = this.state.session;
    session.client_kid = e.target.value;
    this.setState({session: session}, () => {
      this.saveSession(false);
    });
  }
  
  runAuth() {
    this.saveSession(false)
    .then(() => {
      return apiManager.request("exec/auth/" + this.state.client.client_id)
      .then((res) => {
        this.getSession()
        .then(() => {
          this.showHelp(false, 'exec/auth', res);
        });
      })
      .fail((err) => {
        messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_auth_error")});
        this.showHelp(false, 'exec/token', err.responseJSON);
        this.getSession();
      });
    });
  }

  runToken() {
    this.saveSession(false)
    .then(() => {
      return apiManager.request("exec/token/" + this.state.client.client_id, "POST")
      .then((res) => {
        this.getSession()
        .then(() => {
          this.showHelp(false, 'exec/token', res);
          routage.addRoute("esras/run/" + this.state.client.client_id + "/tokenResult");
        });
      })
      .fail((err) => {
        messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_token_error")});
        this.showHelp(false, 'exec/token', err.responseJSON);
        this.getSession();
      });
    });
  }

  changeUserinfoGetJwt() {
    this.setState({userinfoGetJwt: !this.state.userinfoGetJwt});
  }
  
  runUserinfo() {
    this.saveSession(false)
    .then(() => {
      let getJwt = "";
      if (this.state.userinfoGetJwt) {
        getJwt = "?jwt";
      }
      return apiManager.request("exec/userinfo/" + this.state.client.client_id + getJwt, "POST")
      .then((res) => {
        this.getSession()
        .then(() => {
          this.showHelp(false, 'exec/userinfo', res);
        });
      })
      .fail((err) => {
        messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_userinfo_error")});
        this.showHelp(false, 'exec/userinfo', err.responseJSON);
        this.getSession();
      });
    });
  }
  
  selectTokenTarget(e) {
    this.setState({token_target: e.target.value});
  }

  runIntrospection() {
    let session = this.state.session;
    session.token_target_type_hint = this.state.token_target;
    if (this.state.token_target === "refresh_token") {
      session.token_target = session.refresh_token;
    } else if (this.state.token_target === "id_token") {
      session.token_target = session.id_token;
    } else {
      session.token_target = session.access_token;
    }
    this.setState({session: session}, () => {
      this.saveSession(false)
      .then(() => {
        let getJwt = "";
        if (this.state.userinfoGetJwt) {
          getJwt = "?jwt";
        }
        return apiManager.request("exec/introspection/" + this.state.client.client_id + getJwt, "POST")
        .then((res) => {
          this.setState({introspection: res.result}, () => {
            this.getSession()
            .then(() => {
              this.showHelp(false, 'exec/introspection', res);
            });
          });
        })
        .fail((err) => {
          messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_introspection_error")});
          this.showHelp(false, 'exec/introspection', err.responseJSON);
          this.getSession();
          this.setState({introspection: {}});
        });
      });
    });
  }

  runRevocation() {
    let session = this.state.session;
    session.token_target_type_hint = this.state.token_target;
    if (this.state.token_target === "refresh_token") {
      session.token_target = session.refresh_token;
    } else if (this.state.token_target === "id_token") {
      session.token_target = session.id_token;
    } else {
      session.token_target = session.access_token;
    }
    this.setState({session: session}, () => {
      this.saveSession(false)
      .then(() => {
        return apiManager.request("exec/revocation/" + this.state.client.client_id, "POST")
        .then((res) => {
          this.getSession()
          .then(() => {
            this.showHelp(false, 'exec/revocation', res);
          });
        })
        .fail((err) => {
          messageDispatcher.sendMessage("Notification", {type: "danger", message: i18next.t("client_run_revocation_error")});
          this.showHelp(false, 'exec/revocation', err.responseJSON);
          this.getSession();
        });
      });
    });
  }

  showHelp(e, help, result = false) {
    if (e) {
      e.preventDefault();
    }
    let messageJsx = {
      title: i18next.t("help_title"),
      message: ""
    };
    if (help === 'error') {
      messageJsx.title = i18next.t("help_error_title");
      let errorJsx = "", errorDescriptionJsx = "", errorUriJsx = "";
      if (this.state.session.error) {
        errorJsx =
          <div>
            <p className="alert alert-warning">{i18next.t("help_error")}</p>
            <code>{this.state.session.error}</code>
          </div>
      }
      if (this.state.session.error_description) {
        errorDescriptionJsx =
          <div>
            <hr/>
            <p className="alert alert-warning">{i18next.t("help_error_description")}</p>
            <code>{this.state.session.error_description}</code>
          </div>
      }
      if (this.state.session.error_uri) {
        errorUriJsx =
          <div>
            <hr/>
            <p className="alert alert-warning">{i18next.t("help_error_uri")}</p>
            <code>{this.state.session.error_uri}</code>
          </div>
      }
      messageJsx.message = 
        <p>
          {errorJsx}
          {errorDescriptionJsx}
          {errorUriJsx}
        </p>
    } else if (help === 'client_id') {
      messageJsx.message = <p>{i18next.t("help_client_id")}</p>
    } else if (help === 'name') {
      messageJsx.message = <p>{i18next.t("help_name")}</p>
    } else if (help === 'client_secret') {
      messageJsx.message = <p>{i18next.t("help_client_secret")}</p>
    } else if (help === 'redirect_uris') {
      messageJsx.message = <p>{i18next.t("help_redirect_uris_exec")}</p>
    } else if (help === 'response_type') {
      messageJsx.message = <p>{i18next.t("help_response_type")}</p>
    } else if (help === 'auth_method') {
      messageJsx.message = <p>{i18next.t("help_auth_method")}</p>
    } else if (help === 'auth_method_parameters') {
      messageJsx.message = <p>{i18next.t("help_auth_method_parameters")}</p>
    } else if (help === 'scope') {
      messageJsx.message = <p>{i18next.t("help_scope")}</p>
    } else if (help === 'state') {
      messageJsx.message = <p>{i18next.t("help_state")}</p>
    } else if (help === 'nonce') {
      messageJsx.message = <p>{i18next.t("help_nonce")}</p>
    } else if (help === 'code') {
      messageJsx.message = <p>{i18next.t("help_code")}</p>
    } else if (help === 'access_token') {
      messageJsx.message = <p>{i18next.t("help_access_token")}</p>
    } else if (help === 'access_token_show') {
      messageJsx.message =
      <div>
        <p className="alert alert-secondary">{i18next.t("help_access_token_payload")}</p>
        <pre>
          {JSON.stringify(this.state.session.access_token_payload, null, 2)}
        </pre>
      </div>
    } else if (help === 'refresh_token') {
      messageJsx.message = <p>{i18next.t("help_refresh_token")}</p>
    } else if (help === 'id_token') {
      messageJsx.message = <p>{i18next.t("help_id_token")}</p>
    } else if (help === 'id_token_show') {
      messageJsx.message =
      <div>
        <p className="alert alert-secondary">{i18next.t("help_id_token_payload")}</p>
        <pre>
          {JSON.stringify(this.state.session.id_token_payload, null, 2)}
        </pre>
      </div>
    } else if (help === 'exec/auth') {
      if (this.state.authMethod & constant.authMethod.Get) {
        let authLocation = result.url.split('?')[0];
        let authParams = getQueryParams(result.url.split('?')[1]);
        let authParamsJsx = [];
        Object.keys(authParams).forEach(param => {
          if (param === 'client_id') {
            authParamsJsx.push(
              <p key={param}>
                <code>
                  <span className="text-primary elt-left">
                    {param} = {authParams[param]}
                  </span>
                </code>
                :
                <span className="elt-right">
                  {i18next.t("help_client_id")}
                </span>
              </p>
            );
          } else if (param === 'redirect_uri') {
            authParamsJsx.push(
              <p key={param}>
                <code>
                  <span className="text-primary elt-left">
                    {param} = {authParams[param]}
                  </span>
                </code>
                :
                <span className="elt-right">
                  {i18next.t("help_redirect_uris_exec")}
                </span>
              </p>
            );
          } else if (param === 'response_type') {
            authParamsJsx.push(
              <p key={param}>
                <code>
                  <span className="text-primary elt-left">
                    {param} = {authParams[param]}
                  </span>
                </code>
                :
                <span className="elt-right">
                  {i18next.t("help_response_type")}
                </span>
              </p>
            );
          } else if (param === 'state') {
            authParamsJsx.push(
              <p key={param}>
                <code>
                  <span className="text-primary elt-left">
                    {param} = {authParams[param]}
                  </span>
                </code>
                :
                <span className="elt-right">
                  {i18next.t("help_state")}
                </span>
              </p>
            );
          } else if (param === 'scope') {
            authParamsJsx.push(
              <p key={param}>
                <code>
                  <span className="text-primary elt-left">
                    {param} = {authParams[param]}
                  </span>
                </code>
                :
                <span className="elt-right">
                  {i18next.t("help_scope")}
                </span>
              </p>
            );
          } else if (param === 'nonce') {
            authParamsJsx.push(
              <p key={param}>
                <code>
                  <span className="text-primary elt-left">
                    {param} = {authParams[param]}
                  </span>
                </code>
                :
                <span className="elt-right">
                  {i18next.t("help_nonce")}
                </span>
              </p>
            );
          } else if (param === 'code_challenge_method') {
            authParamsJsx.push(
              <p key={param}>
                <code>
                  <span className="text-primary elt-left">
                    {param} = {authParams[param]}
                  </span>
                </code>
                :
                <span className="elt-right">
                  {i18next.t("help_code_challenge_method")}
                </span>
              </p>
            );
          } else if (param === 'code_challenge') {
            authParamsJsx.push(
              <p key={param}>
                <code>
                  <span className="text-primary elt-left">
                    {param} = {authParams[param]}
                  </span>
                </code>
                :
                <span className="elt-right">
                  {i18next.t("help_code_challenge")}
                </span>
              </p>
            );
          }
        });
        messageJsx.message =
          <div>
            <p className="alert alert-secondary">{i18next.t("help_exec_auth")}</p>
            <code><a href={result.url} className="text-success">{result.url}</a></code>
            <hr/>
            <p className="alert alert-secondary">{i18next.t("help_exec_auth_params")}</p>
            {authParamsJsx}
          </div>
      } else {
        let requestSplitted = result.request.split("\r\n"), requestFormatted = [], responseSplitted = result.response.split("\r\n"), responseFormatted = [];
        requestSplitted.forEach(line => {
          if (line.length > 80) {
            for (var i = 0; i < line.length; i += (i?79:80)) {
              if (!i) {
                requestFormatted.push(line.substr(i, 80));
              } else {
                requestFormatted.push(" " + line.substr(i, 79));
              }
            }
          } else {
            requestFormatted.push(line);
          }
        });
        responseSplitted.forEach(line => {
          if (line.length > 80) {
            for (var i = 0; i < line.length; i += (i?79:80)) {
              if (!i) {
                responseFormatted.push(line.substr(i, 80));
              } else {
                responseFormatted.push(" " + line.substr(i, 79));
              }
            }
          } else {
            responseFormatted.push(line);
          }
        });
        messageJsx.message =
          <div>
            <p className="alert alert-secondary">{i18next.t("help_exec_auth")}</p>
            <code><a href={result.url} className="text-success">{result.url}</a></code>
            <hr/>
            <p className="alert alert-secondary">{i18next.t("help_exec_request")}</p>
            <pre>{requestFormatted.join("\n")}</pre>
            <p className="alert alert-secondary">{i18next.t("help_exec_response")}</p>
            <pre>{responseFormatted.join("\n")}</pre>
          </div>
      }
    } else if (help === 'exec/token') {
      let requestSplitted = result.request.split("\r\n"), requestFormatted = [], responseSplitted = result.response.split("\r\n"), responseFormatted = [];
      requestSplitted.forEach(line => {
        if (line.length > 80) {
          for (var i = 0; i < line.length; i += (i?79:80)) {
            if (!i) {
              requestFormatted.push(line.substr(i, 80));
            } else {
              requestFormatted.push(" " + line.substr(i, 79));
            }
          }
        } else {
          requestFormatted.push(line);
        }
      });
      responseSplitted.forEach(line => {
        if (line.length > 80) {
          for (var i = 0; i < line.length; i += (i?79:80)) {
            if (!i) {
              responseFormatted.push(line.substr(i, 80));
            } else {
              responseFormatted.push(" " + line.substr(i, 79));
            }
          }
        } else {
          responseFormatted.push(line);
        }
      });
      messageJsx.message =
        <div>
          <p className="alert alert-secondary">{i18next.t("help_exec_token")}</p>
          <hr/>
          <p className="alert alert-secondary">{i18next.t("help_exec_request")}</p>
          <pre>{requestFormatted.join("\n")}</pre>
          <p className="alert alert-secondary">{i18next.t("help_exec_response")}</p>
          <pre>{responseFormatted.join("\n")}</pre>
        </div>
    } else if (help === 'exec/userinfo') {
      let requestSplitted = result.request.split("\r\n"), requestFormatted = [], responseSplitted = result.response.split("\r\n"), responseFormatted = [];
      requestSplitted.forEach(line => {
        if (line.length > 80) {
          for (var i = 0; i < line.length; i += (i?79:80)) {
            if (!i) {
              requestFormatted.push(line.substr(i, 80));
            } else {
              requestFormatted.push(" " + line.substr(i, 79));
            }
          }
        } else {
          requestFormatted.push(line);
        }
      });
      responseSplitted.forEach(line => {
        if (line.length > 80) {
          for (var i = 0; i < line.length; i += (i?79:80)) {
            if (!i) {
              responseFormatted.push(line.substr(i, 80));
            } else {
              responseFormatted.push(" " + line.substr(i, 79));
            }
          }
        } else {
          responseFormatted.push(line);
        }
      });
      messageJsx.message =
        <div>
          <p className="alert alert-secondary">{i18next.t("help_exec_userinfo")}</p>
          <hr/>
          <p className="alert alert-secondary">{i18next.t("help_exec_request")}</p>
          <pre>{requestFormatted.join("\n")}</pre>
          <p className="alert alert-secondary">{i18next.t("help_exec_response")}</p>
          <pre>{responseFormatted.join("\n")}</pre>
        </div>
    } else if (help === 'exec/introspection') {
      let requestSplitted = result.request.split("\r\n"), requestFormatted = [], responseSplitted = result.response.split("\r\n"), responseFormatted = [];
      requestSplitted.forEach(line => {
        if (line.length > 80) {
          for (var i = 0; i < line.length; i += (i?79:80)) {
            if (!i) {
              requestFormatted.push(line.substr(i, 80));
            } else {
              requestFormatted.push(" " + line.substr(i, 79));
            }
          }
        } else {
          requestFormatted.push(line);
        }
      });
      responseSplitted.forEach(line => {
        if (line.length > 80) {
          for (var i = 0; i < line.length; i += (i?79:80)) {
            if (!i) {
              responseFormatted.push(line.substr(i, 80));
            } else {
              responseFormatted.push(" " + line.substr(i, 79));
            }
          }
        } else {
          responseFormatted.push(line);
        }
      });
      let resultJsx;
      if (result.result) {
        if (result.result.active) {
          resultJsx = <p className="alert alert-success">{i18next.t("help_exec_introspect_active")}</p>
        } else {
          resultJsx = <p className="alert alert-warning">{i18next.t("help_exec_introspect_inactive")}</p>
        }
      } else {
        resultJsx = <p className="alert alert-danger">{i18next.t("help_exec_introspect_error")}</p>
      }
      messageJsx.message =
        <div>
          <p className="alert alert-secondary">{i18next.t("help_exec_introspect")}</p>
          <hr/>
          {resultJsx}
          <p className="alert alert-secondary">{i18next.t("help_exec_request")}</p>
          <pre>{requestFormatted.join("\n")}</pre>
          <p className="alert alert-secondary">{i18next.t("help_exec_response")}</p>
          <pre>{responseFormatted.join("\n")}</pre>
        </div>
    } else if (help === 'exec/revocation') {
      let requestSplitted = result.request.split("\r\n"), requestFormatted = [], responseSplitted = result.response.split("\r\n"), responseFormatted = [];
      requestSplitted.forEach(line => {
        if (line.length > 80) {
          for (var i = 0; i < line.length; i += (i?79:80)) {
            if (!i) {
              requestFormatted.push(line.substr(i, 80));
            } else {
              requestFormatted.push(" " + line.substr(i, 79));
            }
          }
        } else {
          requestFormatted.push(line);
        }
      });
      responseSplitted.forEach(line => {
        if (line.length > 80) {
          for (var i = 0; i < line.length; i += (i?79:80)) {
            if (!i) {
              responseFormatted.push(line.substr(i, 80));
            } else {
              responseFormatted.push(" " + line.substr(i, 79));
            }
          }
        } else {
          responseFormatted.push(line);
        }
      });
      messageJsx.message =
        <div>
          <p className="alert alert-secondary">{i18next.t("help_exec_revocation")}</p>
          <hr/>
          <p className="alert alert-secondary">{i18next.t("help_exec_request")}</p>
          <pre>{requestFormatted.join("\n")}</pre>
          <p className="alert alert-secondary">{i18next.t("help_exec_response")}</p>
          <pre>{responseFormatted.join("\n")}</pre>
        </div>
    } else if (help === 'client_jwks') {
      messageJsx.message = 
      <div>
        <p>{i18next.t("help_client_jwks")}</p>
        <h4>{i18next.t("help_client_jwks_warning")}</h4>
        <p>{i18next.t("help_client_jwks_warning_message")}</p>
      </div>
    } else if (help === 'token_method') {
      messageJsx.message = <p>{i18next.t("help_token_method")}</p>
    } else if (help === 'grant_type') {
      messageJsx.message = <p>{i18next.t("help_grant_type")}</p>
    } else if (help === 'userinfo') {
      messageJsx.message = <p>{i18next.t("help_userinfo")}</p>
    } else if (help === 'userinfo_get_jwt') {
      messageJsx.message = <p>{i18next.t("help_userinfo_get_jwt")}</p>
    } else if (help === 'introspection') {
      messageJsx.message = <p>{i18next.t("help_introspection")}</p>
    } else if (help === 'introspection_get_jwt') {
      messageJsx.message = <p>{i18next.t("help_introspection_get_jwt")}</p>
    } else if (help === 'revocation') {
      messageJsx.message = <p>{i18next.t("help_revocation")}</p>
    } else if (help === 'token_target') {
      messageJsx.message = <p>{i18next.t("help_token_target")}</p>
    }
    this.setState({showMessage: true, message: messageJsx}, () => {
      var myModal = new bootstrap.Modal(document.getElementById('messageModal'), {
        keyboard: true
      });
      myModal.show();
    });
  }

  closeHelp() {
    var myModalEl = document.getElementById('messageModal');
    var modal = bootstrap.Modal.getInstance(myModalEl);
    modal.hide();
    this.setState({showMessage: false, message: false});
  }

  render() {
    let scopeListJsx = [
      <option value="" key={-2}>{i18next.t("client_run_scopes_available")}</option>
    ], responseTypesJsx = [];
    this.state.oidcConfig.config.scopes_supported.forEach((scope, index) => {
      scopeListJsx.push(
        <option value={scope} key={index}>{scope}</option>
      );
    });
    let messageJsx;
    if (this.state.showMessage) {
      messageJsx = <Message title={this.state.message.title} message={this.state.message.message} cb={this.closeHelp} />
    }
    let showCredentials = "", highlightCredentials = " collapsed",
        showAuth = "", highlightAuth = " collapsed",
        showToken = "", highlightToken = " collapsed",
        showTokenResults = "", highlightTokenResults = " collapsed",
        showUserinfo = "", highlightUserinfo = " collapsed",
        showTokenIntrospection = "", highlightTokenIntrospection = " collapsed";
    if (this.state.menu === "credentals") {
      showCredentials = " show";
      highlightCredentials = "";
    } else if (this.state.menu === "auth") {
      showAuth = " show";
      highlightAuth = "";
    } else if (this.state.menu === "token") {
      showToken = " show";
      highlightToken = "";
    } else if (this.state.menu === "tokenResult") {
      showTokenResults = " show";
      highlightTokenResults = ""
    }
    let errorJsx;
    if (this.state.session.error) {
      errorJsx =
        <a href="#" onClick={(e) => this.showHelp(e, 'error')} className="elt-right" title={i18next.t("help_error_title")}>
          <span className="badge rounded-pill bg-danger">
            <i className="fa fa-exclamation-triangle" aria-hidden="true"></i>
          </span>
        </a>
    }
    let clientJwksError = "";
    if (!this.state.jwksValid) {
      clientJwksError = " invalid";
    }
    let userinfoJsx = "";
    if (this.state.session.userinfo) {
      try {
        userinfoJsx = JSON.stringify(JSON.parse(this.state.session.userinfo), null, 2);
      } catch (e) {
        userinfoJsx = this.state.session.userinfo;
      }
    }
    let clientKidListJsx = [<option value="" key={-1}>{i18next.t("client_run_client_kid_first")}</option>];
    this.state.session.client_jwks.keys.forEach((jwk, index) => {
      clientKidListJsx.push(<option value={jwk.kid} key={index}>{jwk.alg + " - " + jwk.kid}</option>);
    });
    return (
      <div>
        <h2>
          {i18next.t("client_run")}{errorJsx}
        </h2>
        <div className="accordion" id="accordionExec">
          <div className="accordion-item">
            <h2 className="accordion-header" id="headingCredentials">
              <button className={"accordion-button"+highlightCredentials} type="button" data-bs-toggle="collapse" data-bs-target="#collapseCredentials" aria-expanded="false" aria-controls="collapseCredentials">
                {i18next.t("client_run_credentials")}
              </button>
            </h2>
            <div id="collapseCredentials" className={"accordion-collapse collapse"+showCredentials} aria-labelledby="headingCredentials" data-bs-parent="#accordionExec">
              <div className="accordion-body">
                <div className="mb-3">
                  <label htmlFor="client_name" className="form-label">
                    {i18next.t("client_run_client_name")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'name')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <input type="text" className="form-control" disabled={true} value={this.state.client.name} />
                </div>
                <div className="mb-3">
                  <label htmlFor="client_id" className="form-label">
                    {i18next.t("client_run_client_id")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'client_id')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <input type="text" className="form-control" disabled={true} value={this.state.client.client_id} />
                </div>
                <div className="mb-3">
                  <label htmlFor="redirect_uris" className="form-label">
                    {i18next.t("client_run_redirect_uris")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'redirect_uris')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <input type="text" className="form-control" disabled={true} value={this.state.client.redirect_uris[0]} />
                </div>
                <div className="mb-3">
                  <label htmlFor="client_id" className="form-label">
                    {i18next.t("client_run_client_secret")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'client_secret')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <input type="text" className="form-control" value={this.state.client.client_secret} onChange={(e) => this.changeParam(e, 'client_secret')} />
                </div>
                <div className="mb-3">
                  <label htmlFor="client_jwks" className="form-label">
                    {i18next.t("client_run_client_jwks")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'client_jwks')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <textarea className="form-control" value={this.state.client_jwks} onChange={this.changeClientJwks} rows="6"></textarea>
                  {!this.state.jwksValid?<span className="text-danger">{i18next.t("client_run_client_jwks_error")}</span>:""}
                </div>
                <div className="mb-3">
                  <label htmlFor="client_kid" className="form-label">
                    {i18next.t("client_run_client_kid")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'client_kid')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <select className="form-select" value={this.state.session['client-kid']} onChange={this.selectClientKid}>
                    {clientKidListJsx}
                  </select>
                </div>
              </div>
            </div>
          </div>
          <div className="accordion-item">
            <h2 className="accordion-header" id="headingAuth">
              <button className={"accordion-button"+highlightAuth} type="button" data-bs-toggle="collapse" data-bs-target="#collapseAuth" aria-expanded="true" aria-controls="collapseAuth">
                {i18next.t("client_run_auth_request")}
              </button>
            </h2>
            <div id="collapseAuth" className={"accordion-collapse collapse"+showAuth} aria-labelledby="headingAuth" data-bs-parent="#accordionExec">
              <div className="accordion-body">
                <div className="mb-3">
                  <label htmlFor="response_type" className="form-label">
                    {i18next.t("client_run_response_type")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'response_type')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <select className="form-select" value={this.state.session.response_type} onChange={this.selectResponseType}>
                    <option value={constant.responseType.code}>code</option>
                    <option value={constant.responseType.token}>token</option>
                    <option value={constant.responseType.id_token}>id_token</option>
                    <option value={constant.responseType.code|constant.responseType.token}>code token</option>
                    <option value={constant.responseType.code|constant.responseType.id_token}>code id_token</option>
                    <option value={constant.responseType.token|constant.responseType.id_token}>token id_token</option>
                    <option value={constant.responseType.token|constant.responseType.code|constant.responseType.id_token}>code token id_token</option>
                    <option value={constant.responseType.none}>none</option>
                  </select>
                </div>
                <div className="mb-3">
                  <label htmlFor="auth_method" className="form-label">
                    {i18next.t("client_run_auth_method")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'auth_method')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <select className="form-select" value={this.state.authMethod} onChange={this.selectAuthMethod}>
                    <option value={constant.authMethod.Get}>GET</option>
                    <option value={constant.authMethod.Post}>POST</option>
                  </select>
                </div>
                {/*<div className="mb-3">
                  <label htmlFor="auth_method_parameters" className="form-label">
                    {i18next.t("client_run_auth_method_parameters")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'auth_method_parameters')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <select className="form-select" value={this.state.authMethodParams} onChange={this.selectAuthMethodParams}>
                    <option value={0}>Plain</option>
                    <option value={constant.authMethod.JwtSignSecret}>Jwt Sign Secret</option>
                    <option value={constant.authMethod.JwtSignPrivkey}>Jwt Sign Privkey</option>
                    <option value={constant.authMethod.JwtEncryptSecret}>Jwt Encrypt Secret</option>
                    <option value={constant.authMethod.JwtEncryptPubkey}>Jwt Encrypt Pubkey</option>
                  </select>
                </div>*/}
                <div className="mb-3">
                  <label htmlFor="scope" className="form-label">
                    {i18next.t("client_run_scope")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'scope')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <select className="form-select" value="" onChange={this.selectScope}>
                    {scopeListJsx}
                  </select>
                  <input type="text" className="form-control" value={this.state.session.scope} onChange={this.changeScope} />
                </div>
                <div className="mb-3">
                  <label htmlFor="state" className="form-label">
                    {i18next.t("client_run_state")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'state')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <div className="input-group mb-3">
                    <input type="text" maxLength="128" className="form-control" value={this.state.session.state||""} onChange={(e) => this.changeParam(e, 'state')} />
                    <button className="btn btn-outline-secondary" type="button" title={i18next.t("client_run_save")} onClick={(e) => this.saveSession(false)}>
                      <i className="fa fa-save" aria-hidden="true"></i>
                    </button>
                    <button className="btn btn-outline-secondary" type="button" title={i18next.t("client_run_generate")} onClick={() => this.generateParam('state')}>
                      <i className="fa fa-cogs" aria-hidden="true"></i>
                    </button>
                  </div>
                </div>
                <div className="mb-3">
                  <label htmlFor="nonce" className="form-label">
                    {i18next.t("client_run_nonce")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'nonce')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <div className="input-group mb-3">
                    <input type="text" className="form-control" value={this.state.session.nonce||""} onChange={(e) => this.changeParam(e, 'nonce')} />
                    <button className="btn btn-outline-secondary" type="button" title={i18next.t("client_run_save")} onClick={(e) => this.saveSession(false)}>
                      <i className="fa fa-save" aria-hidden="true"></i>
                    </button>
                    <button className="btn btn-outline-secondary" type="button" title={i18next.t("client_run_generate")} onClick={() => this.generateParam('nonce')}>
                      <i className="fa fa-cogs" aria-hidden="true"></i>
                    </button>
                  </div>
                </div>
                <div className="mb-3">
                  <label htmlFor="pkce_method" className="form-label">
                    {i18next.t("client_run_pkce_method")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'pkce_method')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <select className="form-select" value={this.state.session.pkce_method} onChange={this.selectPkceMethod}>
                    <option value="0">None</option>
                    <option value="2">S256</option>
                  </select>
                </div>
                <div className="mb-3">
                  <label htmlFor="client_id" className="form-label">
                    {i18next.t("client_run_pkce_code_verifier")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'pkce_code_verifier')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <div className="input-group mb-3">
                    <input type="text" className="form-control" value={this.state.session.pkce_code_verifier||""} onChange={(e) => this.changeParam(e, 'pkce_code_verifier')} disabled={this.state.session.pkce_method!==2} />
                    <button className="btn btn-outline-secondary" type="button" title={i18next.t("client_run_save")} onClick={(e) => this.saveSession(false)}>
                      <i className="fa fa-save" aria-hidden="true"></i>
                    </button>
                    <button className="btn btn-outline-secondary" type="button" title={i18next.t("client_run_generate")} onClick={() => this.generateParam('pkce')}>
                      <i className="fa fa-cogs" aria-hidden="true"></i>
                    </button>
                  </div>
                </div>
                <div className="mb-3">
                  <button type="button" onClick={() => this.runAuth()} className="btn btn-primary">
                    {i18next.t("client_run_auth_btn")}
                  </button>
                </div>
              </div>
            </div>
          </div>
          <div className="accordion-item">
            <h2 className="accordion-header" id="headingToken">
              <button className={"accordion-button"+highlightToken} type="button" data-bs-toggle="collapse" data-bs-target="#collapseToken" aria-expanded="false" aria-controls="collapseToken">
                {i18next.t("client_run_token_request")}
              </button>
            </h2>
            <div id="collapseToken" className={"accordion-collapse collapse"+showToken} aria-labelledby="headingToken" data-bs-parent="#accordionExec">
              <div className="accordion-body">
                <div className="mb-3">
                  <label htmlFor="code" className="form-label">
                    {i18next.t("client_run_code")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'code')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <input type="text" className="form-control" value={this.state.session.code} disabled={true} />
                </div>
                <div className="mb-3">
                  <label htmlFor="grant_type" className="form-label">
                    {i18next.t("client_run_grant_type")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'grant_type')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <select className="form-select" value={this.state.session.response_type} onChange={this.selectResponseType}>
                    <option value={constant.grantType.code}>code</option>
                    {/*<option value={constant.grantType.password}>password</option>*/}
                    <option value={constant.grantType.client_credentials}>client_credentials</option>
                    <option value={constant.grantType.refresh_token}>refresh_token</option>
                    {/*<option value={constant.grantType.device_code}>device_code</option>
                    <option value={constant.grantType.ciba}>ciba</option>*/}
                  </select>
                </div>
                <div className="mb-3">
                  <label htmlFor="token_method" className="form-label">
                    {i18next.t("client_run_token_method")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'token_method')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <div className="alert alert-secondary" role="alert">
                    {this.state.client.token_endpoint_auth_method}
                  </div>
                </div>
                <div className="mb-3">
                  <button type="button" onClick={() => this.runToken()} className="btn btn-primary">
                    {i18next.t("client_run_token_btn")}
                  </button>
                </div>
              </div>
            </div>
          </div>
          <div className="accordion-item">
            <h2 className="accordion-header" id="headingTokenResults">
              <button className={"accordion-button"+highlightTokenResults} type="button" data-bs-toggle="collapse" data-bs-target="#collapseTokenResults" aria-expanded="false" aria-controls="collapseTokenResults">
                {i18next.t("client_run_token_results")}
              </button>
            </h2>
            <div id="collapseTokenResults" className={"accordion-collapse collapse"+showTokenResults} aria-labelledby="headingTokenResults" data-bs-parent="#accordionExec">
              <div className="accordion-body">
                <div className="mb-3">
                  <label htmlFor="code" className="form-label">
                    {i18next.t("client_run_code")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'code')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <input type="text" className="form-control" value={this.state.session.code} disabled={true} />
                </div>
                <div className="mb-3">
                  <label htmlFor="access_token" className="form-label">
                    {i18next.t("client_run_access_token")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'access_token')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <div className="input-group mb-3">
                    <textarea className="form-control" value={this.state.session.access_token} disabled={true} rows="6"></textarea>
                    <button className="btn btn-outline-secondary"
                            type="button"
                            title={i18next.t("client_run_show_access_token")}
                            onClick={(e) => this.showHelp(e, 'access_token_show')}
                            disabled={!this.state.session.access_token}>
                      <i className="fa fa-eye" aria-hidden="true"></i>
                    </button>
                  </div>
                </div>
                <div className="mb-3">
                  <label htmlFor="refresh_token" className="form-label">
                    {i18next.t("client_run_refresh_token")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'refresh_token')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <textarea className="form-control" value={this.state.session.refresh_token} disabled={true} rows="6"></textarea>
                </div>
                <div className="mb-3">
                  <label htmlFor="id_token" className="form-label">
                    {i18next.t("client_run_id_token")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'id_token')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <div className="input-group mb-3">
                    <textarea className="form-control" value={this.state.session.id_token} disabled={true} rows="6"></textarea>
                    <button className="btn btn-outline-secondary" type="button" title={i18next.t("client_run_show_id_token")} onClick={(e) => this.showHelp(e, 'id_token_show')}>
                      <i className="fa fa-eye" aria-hidden="true"></i>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="accordion-item">
            <h2 className="accordion-header" id="headingUserinfo">
              <button className={"accordion-button"+highlightUserinfo} type="button" data-bs-toggle="collapse" data-bs-target="#collapseUserinfo" aria-expanded="false" aria-controls="collapseUserinfo">
                {i18next.t("client_run_userinfo")}
              </button>
            </h2>
            <div id="collapseUserinfo" className={"accordion-collapse collapse"+showUserinfo} aria-labelledby="headingUserinfo" data-bs-parent="#accordionExec">
              <div className="accordion-body">
                <div className="mb-3">
                  <button type="button" onClick={() => this.runUserinfo()} className="btn btn-primary">
                    {i18next.t("client_run_userinfo_btn")}
                  </button>
                  <a href="#" onClick={(e) => this.showHelp(e, 'userinfo')}>
                    <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                  </a>
                </div>
                <div className="mb-3 form-check">
                  <input type="checkbox" className="form-check-input" id="userinfo_get_jwt" value={this.state.userinfoGetJwt} onChange={this.changeUserinfoGetJwt} />
                  <label htmlFor="userinfo_get_jwt" className="form-label">
                    {i18next.t("client_run_userinfo_get_jwt")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'userinfo_get_jwt')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                </div>
                <div className="mb-3">
                  <p className="alert alert-secondary">{i18next.t("client_run_userinfo_response")}</p>
                  <pre>{userinfoJsx}</pre>
                </div>
              </div>
            </div>
          </div>
          <div className="accordion-item">
            <h2 className="accordion-header" id="headingTokenIntrospection">
              <button className={"accordion-button"+highlightTokenIntrospection} type="button" data-bs-toggle="collapse" data-bs-target="#collapseTokenIntrospection" aria-expanded="false" aria-controls="collapseTokenIntrospection">
                {i18next.t("client_run_token_introspection")}
              </button>
            </h2>
            <div id="collapseTokenIntrospection" className={"accordion-collapse collapse"+showTokenIntrospection} aria-labelledby="headingTokenIntrospection" data-bs-parent="#accordionExec">
              <div className="accordion-body">
                <div className="mb-3">
                  <button type="button" onClick={() => this.runIntrospection()} className="btn btn-primary">
                    {i18next.t("client_run_introspection_btn")}
                  </button>
                  <a href="#" onClick={(e) => this.showHelp(e, 'introspection')}>
                    <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                  </a>
                  <button type="button" onClick={() => this.runRevocation()} className="btn btn-primary elt-right">
                    {i18next.t("client_run_revocation_btn")}
                  </button>
                  <a href="#" onClick={(e) => this.showHelp(e, 'revocation')}>
                    <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                  </a>
                </div>
                <div className="mb-3">
                  <label htmlFor="grant_type" className="form-label">
                    {i18next.t("client_run_token_target")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'token_target')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                  <select className="form-select" value={this.state.token_target} onChange={this.selectTokenTarget}>
                    <option value="access_token">Access token</option>
                    <option value="refresh_token">Refresh token</option>
                    <option value="id_token">ID token</option>
                  </select>
                </div>
                <div className="mb-3 form-check">
                  <input type="checkbox" className="form-check-input" id="introspection_get_jwt" value={this.state.userinfoGetJwt} onChange={this.changeUserinfoGetJwt} />
                  <label htmlFor="introspection_get_jwt" className="form-label">
                    {i18next.t("client_run_userinfo_get_jwt")}
                    <a href="#" onClick={(e) => this.showHelp(e, 'introspection_get_jwt')}>
                      <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                    </a>
                  </label>
                </div>
                <div className="mb-3">
                  <p className="alert alert-secondary">{i18next.t("client_run_introspection_response")}</p>
                  <pre>{JSON.stringify(this.state.introspection, null, 2)}</pre>
                </div>
              </div>
            </div>
          </div>
        </div>
        {messageJsx}
      </div>
    );
  }
}

export default Exec;
