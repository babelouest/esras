import React, { Component } from 'react';
import i18next from 'i18next';

class Message extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      message: props.message,
      cb: props.cb
    }

    this.closeModal = this.closeModal.bind(this);
  }

  static getDerivedStateFromProps(props, state) {
    return props;
  }
  
  closeModal(e) {
    if (this.state.cb) {
      this.state.cb();
    }
  }
  
	render() {
		return (
      <div className="modal" id="messageModal" tabIndex="-1">
        <div className="modal-dialog modal-md">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">{this.state.title}</h5>
              <button type="button" className="btn-close" data-bs-dismiss="modal" aria-label={i18next.t("close")} onClick={(e) => this.closeModal(e, false)}></button>
            </div>
            <div className="modal-body">
              {this.state.message}
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("close")}</button>
            </div>
          </div>
        </div>
      </div>
		);
	}
}

export default Message;
