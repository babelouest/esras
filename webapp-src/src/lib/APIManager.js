import messageDispatcher from './MessageDispatcher';

class APIManager {
  constructor() {
    this.apiPrefix = "";
  }

  setConfig(apiPrefix) {
    this.apiPrefix = apiPrefix;
  }
  
	request(url, method="GET", data=false, accept="application/json; charset=utf-8") {
    let headers = {
      accept: accept
    };
    let contentType = null;
    let jsonData = !!data?JSON.stringify(data):null;
    if (data) {
      contentType = "application/json; charset=utf-8";
    }
		return $.ajax({
			method: method,
			url: this.apiPrefix + "/" + url,
			data: jsonData,
			contentType: contentType,
			headers: headers
		})
    .fail((err) => {
      if (err.status === 401) {
      }
    });
	}
}

let apiManager = new APIManager();

export default apiManager;
