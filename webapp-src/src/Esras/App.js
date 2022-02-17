import React, { Component } from 'react';

import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';
import apiManager from '../lib/APIManager';

import TopMenu from './TopMenu';
import List from './List';
import Register from './Register';

class App extends Component {
  constructor(props) {
    super(props);

    let redirectUriEsras = window.location.href.substring(0, window.location.href.lastIndexOf('/')) + "/api/client/redirect";
    this.state = {
      profile: false,
      clients: [],
      redirectUriEsras: redirectUriEsras,
      curClient: {
        name: "",
        redirect_uris: [redirectUriEsras],
        client_confidential: true,
        token_endpoint_auth_method: 'client_secret_basic',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code', 'token', 'id_token'],
        jwks: ""
      },
      nav: false
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
            redirect_uris: [this.state.redirectUriEsras],
            client_confidential: true,
            token_endpoint_auth_method: 'client_secret_basic',
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code', 'token', 'id_token'],
            jwks: ""
          }});
        } else if (message.target === 'edit') {
          this.setState({nav: 'register', curClient: message.client.registration});
        }
      } else if (message.action === 'logout') {
        apiManager.request("profile", "DELETE")
        .then(() => {
          this.setState({profile: false, clients: [], nav: false});
        });
      }
    });

    this.getProfile()
    .then(() => {
      this.getClientList();
    });
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

	render() {
    var body;
    if (this.state.nav === 'register') {
      body = <Register client={this.state.curClient} />
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
