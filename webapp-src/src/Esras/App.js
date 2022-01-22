import React, { Component } from 'react';

import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';
import apiManager from '../lib/APIManager';

import TopMenu from './TopMenu';
import Register from './Register';

class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      profile: false,
      clients: [],
      nav: false
    };

    apiManager.setConfig("api");

    messageDispatcher.subscribe('App', (message) => {
      if (message.action === 'nav') {
        if (message.target === 'list') {
          this.setState({nav: false});
        } else if (message.target === 'register') {
          this.setState({nav: 'register'});
        }
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
      body = <Register/>
    } else {
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
