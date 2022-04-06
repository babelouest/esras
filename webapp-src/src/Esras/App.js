import React, { Component } from 'react';

import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';
import apiManager from '../lib/APIManager';
import routage from '../lib/Routage';

import TopMenu from './TopMenu';
import List from './List';
import Register from './Register';
import Exec from './Exec';
import Message from './Message';

class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      profile: false,
      clients: [],
      oidcConfig: false,
      curClient: {
        name: "",
        redirect_uris: [],
        client_confidential: true,
        token_endpoint_auth_method: 'client_secret_basic',
        grant_types: ['authorization_code', 'implicit', 'client_credentials', 'refresh_token', 'delete_token', 'device_authorization', 'urn:openid:params:grant-type:ciba'],
        response_types: ['code', 'token', 'id_token'],
        jwks: ""
      },
      nav: false,
      runMenu: false,
      showMessage: false,
      message: {
        title: i18next.t("help_esras_title"),
        message: <div>
          <p>{i18next.t("help_esras")}</p>
          <a href="https://github.com/babelouest/esras/issues">https://github.com/babelouest/esras/issues</a>
          <hr/>
          <p>Copyright 2022 - Nicolas Mora <a href="mailto:mail@babelouest.io">mail@babelouest.io</a></p>
        </div>
      }
    };

    apiManager.setConfig("api");

    messageDispatcher.subscribe('App', (message) => {
      if (message.action === 'nav') {
        if (message.target === 'list') {
          this.setState({nav: false});
        } else if (message.target === 'reload') {
          this.getClientList()
          .then(() => {
            this.setState({nav: false});
          });
        } else if (message.target === 'register') {
          this.setState({nav: 'register', curClient: {
            name: "",
            redirect_uris: [this.state.oidcConfig.test_client_redirect_uri],
            client_confidential: true,
            token_endpoint_auth_method: 'client_secret_basic',
            grant_types: ['authorization_code', 'implicit', 'client_credentials', 'refresh_token', 'delete_token', 'device_authorization', 'urn:openid:params:grant-type:ciba'],
            response_types: ['code', 'token', 'id_token'],
            jwks: "",
            backchannel_client_notification_endpoint: this.state.oidcConfig.test_client_ciba_notification_endpoint,
            backchannel_user_code_parameter: false,
            sector_identifier_uri: [this.state.oidcConfig.test_client_redirect_uri, this.state.oidcConfig.test_client_ciba_notification_endpoint]
          }});
        } else if (message.target === 'edit') {
          this.setState({nav: 'register', curClient: message.client.registration});
        } else if (message.target === 'exec') {
          this.setState({nav: 'exec', curClient: message.client.registration, runMenu: message.menu});
        }
      } else if (message.action === 'logout') {
        apiManager.request("profile", "DELETE")
        .then(() => {
          this.setState({profile: false, clients: [], nav: false});
        });
      } else if (message.action === 'help') {
        this.showHelp();
      }
    });

    routage.addChangeRouteCallback((route) => {
      this.gotoRoute(route);
    });

    this.getOidcConfig()
    .then(() => {
      this.getProfile()
      .then(() => {
        this.getClientList()
        .then(() => {
          this.gotoRoute(routage.getCurrentRoute());
        });
      });
    });
    
    this.gotoRoute = this.gotoRoute.bind(this);
    this.showHelp = this.showHelp.bind(this);
    this.closeModal = this.closeModal.bind(this);
  }
  
  getProfile() {
    return apiManager.request("profile")
    .then((res) => {
      this.setState({profile: res});
    });
  }
  
  getClientList() {
    return apiManager.request("client")
    .then((res) => {
      this.setState({clients: res});
    });
  }

  getOidcConfig() {
    return apiManager.request("oidc_config")
    .then((res) => {
      this.setState({oidcConfig: res});
    });
  }

  gotoRoute(route) {
    if (route) {
      let routeSplit = route.split("/");
      if (routeSplit[0] === "esras") {
        if (routeSplit[1] === "register") {
          messageDispatcher.sendMessage("App", {action: 'nav', target: 'register'});
        } else if (routeSplit[1] === "edit") {
          this.state.clients.forEach((client) => {
            if (client.client_id === routeSplit[2]) {
              messageDispatcher.sendMessage("App", {action: 'nav', target: "edit", client: client});
            }
          });
        } else if (routeSplit[1] === "run") {
          this.state.clients.forEach((client) => {
            if (client.client_id === routeSplit[2]) {
              messageDispatcher.sendMessage("App", {action: 'nav', target: "exec", client: client, menu: (routeSplit[3]?routeSplit[3]:false)});
            }
          });
        } else {
          this.setState({nav: false});
        }
      }
    }
  }

  showHelp() {
    this.setState({showMessage: true}, () => {
      var myModal = new bootstrap.Modal(document.getElementById('messageModal'), {
        keyboard: true
      });
      myModal.show();
    });
  }

  closeModal() {
    var myModalEl = document.getElementById('messageModal');
    var modal = bootstrap.Modal.getInstance(myModalEl);
    modal.hide();
    this.setState({showMessage: false});
  }

	render() {
    var body, messageJsx;
    if (this.state.nav === 'register') {
      body = <Register client={this.state.curClient} />
    } else if (this.state.nav === 'exec') {
      body = <Exec client={this.state.curClient} oidcConfig={this.state.oidcConfig} menu={this.state.runMenu} profile={this.state.profile} />
    } else {
      body = <List clients={this.state.clients} />
    }
    if (this.state.showMessage) {
      messageJsx = <Message title={this.state.message.title} message={this.state.message.message} cb={this.closeModal} />
    }
    return (
      <div className="container-fluid">
        <TopMenu profile={this.state.profile}/>
        {body}
        <Notification/>
        {messageJsx}
      </div>
    );
	}
}

export default App;
