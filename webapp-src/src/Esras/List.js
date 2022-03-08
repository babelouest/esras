import React, { Component } from 'react';

import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';
import routage from '../lib/Routage';

import Confirm from './Confirm';
import Message from './Message';

class Register extends Component {
  constructor(props) {
    super(props);

    this.state = {
      clients: props.clients,
      clientShowSecret: {},
      curClient: false,
      showDisableConfirm: false,
      showMessage: false,
      message: {
        title: false,
        message: false
      },
      showStatus: "all"
    };
    
    this.registerNew = this.registerNew.bind(this);
    this.toggleShowSecret = this.toggleShowSecret.bind(this);
    this.showRegistration = this.showRegistration.bind(this);
    this.closeModal = this.closeModal.bind(this);
    this.runClient = this.runClient.bind(this);
    this.editClient = this.editClient.bind(this);
    this.disableClient = this.disableClient.bind(this);
    this.confirmDisableClient = this.confirmDisableClient.bind(this);
    this.changeStatus = this.changeStatus.bind(this);
  }

  static getDerivedStateFromProps(props, state) {
    return props;
  }

  registerNew() {
    routage.addRoute("esras/register");
    messageDispatcher.sendMessage("App", {action: 'nav', target: 'register'});
  }

  toggleShowSecret(e, client_id) {
    let clientShowSecret = this.state.clientShowSecret;
    clientShowSecret[client_id] = !clientShowSecret[client_id];
    this.setState({clientShowSecret: clientShowSecret});
  }

  showRegistration(client) {
    let messageJsx = {
      title: i18next.t("client_show_registration"),
      message: <code><pre>{JSON.stringify(client.registration, null, 2)}</pre></code>
    };
    this.setState({showMessage: true, message: messageJsx}, () => {
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
    this.setState({showMessage: false, message: false});
  }

  runClient(client) {
    routage.addRoute("esras/run/" + client.client_id);
    messageDispatcher.sendMessage("App", {action: 'nav', target: "exec", client: client});
  }

  editClient(client) {
    routage.addRoute("esras/edit/" + client.client_id);
    messageDispatcher.sendMessage("App", {action: 'nav', target: "edit", client: client});
  }

  disableClient(client) {
    this.setState({showDisableConfirm: true, curClient: client}, () => {
      var myModal = new bootstrap.Modal(document.getElementById('confirmModal'), {
        keyboard: true
      });
      myModal.show();
    });
  }
  
  confirmDisableClient(result) {
    if (result) {
      apiManager.request("client/" + this.state.curClient.client_id, "DELETE")
      .then(() => {
        messageDispatcher.sendMessage("App", {action: 'nav', target: "reload"});
      })
      .fail(() => {
        messageDispatcher.sendMessage("Notification", {type: "success", message: i18next.t("register_client_error")});
      });
    }
    var myModalEl = document.getElementById('confirmModal');
    var modal = bootstrap.Modal.getInstance(myModalEl);
    modal.hide();
    this.setState({showDisableConfirm: false, curClient: false});
  }

  changeStatus(e) {
    this.setState({showStatus: e.target.value});
  }

  showHelp(e, help) {
    e.preventDefault();
    let messageJsx = {
      title: i18next.t("help_title"),
      message: ""
    };
    if (help === 'status') {
      messageJsx.message = <p>{i18next.t("help_status")}</p>
    } else if (help === 'name') {
      messageJsx.message = <p>{i18next.t("help_name")}</p>
    } else if (help === 'client_id') {
      messageJsx.message = <p>{i18next.t("help_client_id")}</p>
    } else if (help === 'client_secret') {
      messageJsx.message = <p>{i18next.t("help_client_secret")}</p>
    } else if (help === 'redirect_uris') {
      messageJsx.message = <p>{i18next.t("help_redirect_uris")}</p>
    } else if (help === 'registration') {
      messageJsx.message = <p>{i18next.t("help_registration")}</p>
    } else if (help === 'register') {
      messageJsx.message = <p>{i18next.t("help_register")}</p>
    }
    this.setState({showMessage: true, message: messageJsx}, () => {
      var myModal = new bootstrap.Modal(document.getElementById('messageModal'), {
        keyboard: true
      });
      myModal.show();
    });
  }

  render() {
    let clientListJsx = [], confirmJsx, messageJsx;
    this.state.clients.forEach((client, index) => {
      if ((client.enabled && (this.state.showStatus === 'all' || this.state.showStatus === 'enabled')) || (!client.enabled && (this.state.showStatus === 'all' || this.state.showStatus === 'disabled'))) {
        let redirectUris = [], clientSecretJsx, isDisabledClass, clientStatusJsx;
        client.redirect_uris.forEach((redirectUri, ruIndex) => {
          redirectUris.push(
            <span className="badge bg-primary elt-right" key={ruIndex}>{redirectUri}</span>
          );
        });
        if (this.state.showDisableConfirm) {
          confirmJsx = <Confirm title={i18next.t("client_list_disable_client")} message={i18next.t("client_list_disable_client_message", {name: this.state.curClient.name, client_id: this.state.curClient.client_id})} cb={this.confirmDisableClient} />
        }
        if (this.state.showMessage) {
          messageJsx = <Message title={this.state.message.title} message={this.state.message.message} cb={this.closeModal} />
        }
        if (client.client_secret) {
          if (this.state.clientShowSecret[client.client_id]) {
            clientSecretJsx = 
              <div>
                <a className="btn btn-sm btn-primary elt-left" onClick={(e)=>this.toggleShowSecret(e, client.client_id)}>
                  <i className="fa fa-eye" aria-hidden="true"></i>
                </a>
                <code>
                  {client.client_secret}
                </code>
              </div>
          } else {
            clientSecretJsx =
              <div>
                <a className="btn btn-sm btn-primary elt-left" onClick={(e)=>this.toggleShowSecret(e, client.client_id)}>
                  <i className="fa fa-eye" aria-hidden="true"></i>
                </a>
                <code>
                  ***********
                </code>
              </div>
          }
        } else {
          clientSecretJsx = <i className="fa fa-ban" aria-hidden="true"></i>;
        }
        if (!client.enabled) {
          clientStatusJsx = <span className="badge bg-danger">{i18next.t("client_list_status_disabled")}</span>
          isDisabledClass = "bg-warning";
        } else {
          clientStatusJsx = <span className="badge bg-success">{i18next.t("client_list_status_enabled")}</span>
        }
        clientListJsx.push(
          <tr key={index} className={isDisabledClass}>
            <td>
              {clientStatusJsx}
            </td>
            <td scope="row">
              <code>
                {client.name}
              </code>
            </td>
            <td>
              <code>
                {client.client_id}
              </code>
            </td>
            <td>
              {clientSecretJsx}
            </td>
            <td>
              {redirectUris}
            </td>
            <td className="text-center">
              <button type="button" className="btn btn-sm btn-primary" onClick={() => this.showRegistration(client)} title={i18next.t("client_list_show_registration")}>
                <i className="fa fa-eye" aria-hidden="true"></i>
              </button>
            </td>
            <td>
              <div className="btn-group">
                <button type="button" className="btn btn-sm btn-primary" onClick={() => this.runClient(client)} title={i18next.t("client_list_run_client")} disabled={!client.enabled}>
                  <i className="fa fa-play" aria-hidden="true"></i>
                </button>
                <button type="button" className="btn btn-sm btn-primary" onClick={() => this.editClient(client)} title={i18next.t("client_list_edit_client")} disabled={!client.enabled}>
                  <i className="fa fa-edit" aria-hidden="true"></i>
                </button>
                <button type="button" className="btn btn-sm btn-primary" onClick={() => this.disableClient(client)} title={i18next.t("client_list_disable_client")} disabled={!client.enabled}>
                  <i className="fa fa-trash" aria-hidden="true"></i>
                </button>
              </div>
            </td>
          </tr>
        );
      }
    });
    return (
      <div>
        <h3>
          {i18next.t("client_list_title")}
        </h3>
        <div className="row">
          <div className="col">
            <div className="mb-3">
              <label htmlFor="statusSelect" className="form-label">{i18next.t("client_list_status_select")}</label>
              <select className="form-select" onChange={this.changeStatus} value={this.state.showStatus} id="statusSelect">
                <option value="all">{i18next.t("client_list_status_all")}</option>
                <option value="enabled">{i18next.t("client_list_status_enabled")}</option>
                <option value="disabled">{i18next.t("client_list_status_disabled")}</option>
              </select>
            </div>
          </div>
        </div>
        <table className="table table-striped">
          <thead>
            <tr>
              <th scope="col">
                {i18next.t("client_list_status")}
                <a href="#" onClick={(e) => this.showHelp(e, 'status')}>
                  <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                </a>
              </th>
              <th scope="col">
                {i18next.t("client_list_name")}
                <a href="#" onClick={(e) => this.showHelp(e, 'name')}>
                  <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                </a>
              </th>
              <th scope="col">
                {i18next.t("client_list_client_id")}
                <a href="#" onClick={(e) => this.showHelp(e, 'client_id')}>
                  <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                </a>
              </th>
              <th scope="col">
                {i18next.t("client_list_client_secret")}
                <a href="#" onClick={(e) => this.showHelp(e, 'client_secret')}>
                  <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                </a>
              </th>
              <th scope="col">
                {i18next.t("client_list_redirect_uris")}
                <a href="#" onClick={(e) => this.showHelp(e, 'redirect_uris')}>
                  <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                </a>
              </th>
              <th scope="col" className="text-center">
                {i18next.t("client_list_registration")}
                <a href="#" onClick={(e) => this.showHelp(e, 'registration')}>
                  <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
                </a>
              </th>
              <th>
              </th>
            </tr>
          </thead>
          <tbody>
            {clientListJsx}
          </tbody>
        </table>
        <div className="row">
          <div className="col">
            <button type="button" className="btn btn-primary" onClick={this.registerNew}>
              <i className="fa fa-plus elt-left" aria-hidden="true"></i>
              {i18next.t("register_new")}
            </button>
            <a href="#" onClick={(e) => this.showHelp(e, 'register')}>
              <i className="fa fa-question-circle-o elt-right" aria-hidden="true"></i>
            </a>
          </div>
        </div>
        {confirmJsx}
        {messageJsx}
      </div>
    );
  }
}

export default Register;
