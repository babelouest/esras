import React, { Component } from 'react';

import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import routage from '../lib/Routage';

class TopMenu extends Component {
  constructor(props) {
    super(props);

    this.state = {
      profile: props.profile
    };
    
    this.navigateTo = this.navigateTo.bind(this);
  }
  
  static getDerivedStateFromProps(props, state) {
    return props;
  }
  
  navigateTo(e, menu) {
    e.preventDefault();
    routage.addRoute(menu||"");
    messageDispatcher.sendMessage("App", {action: 'nav', target: menu});
  }
  
  logOut() {
    messageDispatcher.sendMessage("App", {action: 'logout'});
  }
  
	render() {
    var name = "", rightMenuJsx;
    if (this.state.profile) {
      name = this.state.profile.name || this.state.profile.sub;
      rightMenuJsx =
        <ul className="navbar-nav ms-auto flex-nowrap text-right">
          <li className="nav-item">
            <a className="nav-link" onClick={() => this.logOut()} href="#">{i18next.t("log_out")}</a>
          </li>
        </ul>
    }
    return (
      <nav className="navbar navbar-expand-lg nav-pills navbar-light bg-light">
        <div className="container-fluid">
          <a className="navbar-brand"
             href="#"
             onClick={(e) => this.navigateTo(e, 'list')}>
            Esras
          </a>
          <div className="collapse navbar-collapse" id="navbarNav">
            <ul className="navbar-nav ms-auto flex-nowrap text-right">
              <li className="nav-item">
                {name}
              </li>
            </ul>
            {rightMenuJsx}
          </div>
        </div>
      </nav>
    );
	}
}

export default TopMenu;
