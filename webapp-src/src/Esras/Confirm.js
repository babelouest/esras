import React, { Component } from 'react';
import i18next from 'i18next';

class Confirm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      message: props.message,
      cb: props.callback
    }

    this.closeModal = this.closeModal.bind(this);
  }

  static getDerivedStateFromProps(props, state) {
    return props;
  }
  
  closeModal(e, result) {
    if (this.state.cb) {
      this.state.cb(result);
    }
  }
  
	render() {
		return (
      <div className="modal" id="confirmModal" tabIndex="-1">
        <div className="modal-dialog">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">{this.state.title}</h5>
              <button type="button" className="btn-close" data-bs-dismiss="modal" aria-label={i18next.t("close")} onClick={(e) => this.closeModal(e, false)}></button>
            </div>
            <div className="modal-body">
              <p>
                {this.state.message}
              </p>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("close")}</button>
              <button type="button" className="btn btn-primary" onClick={(e) => this.closeModal(e, true)}>{i18next.t("ok")}</button>
            </div>
          </div>
        </div>
      </div>
		);
	}
}

export default Confirm;
