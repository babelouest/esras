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
        grant_types: ['authorization_code', 'implicit', 'client_credentials', 'refresh_token', 'delete_token', 'device_authorization'],
        response_types: ['code', 'token', 'id_token'],
        jwks: "",
        token_endpoint_signing_alg: ""
      },
      nav: false,
      runMenu: false
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
            grant_types: ['authorization_code', 'implicit', 'client_credentials', 'refresh_token', 'delete_token', 'device_authorization'],
            response_types: ['code', 'token', 'id_token'],
            jwks: "",
            token_endpoint_signing_alg: ""
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

	render() {
    var body;
    if (this.state.nav === 'register') {
      body = <Register client={this.state.curClient} />
    } else if (this.state.nav === 'exec') {
      body = <Exec client={this.state.curClient} oidcConfig={this.state.oidcConfig} menu={this.state.runMenu} />
    } else {
      body = <List clients={this.state.clients} />
    }
    return (
      <div className="container-fluid">
        <TopMenu profile={this.state.profile}/>
        {body}
        <Notification/>
      </div>
    );
	}
}

export default App;
