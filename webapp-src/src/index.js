/**
 * 
 * Esras front-end application
 * 
 * Copyright 2022 Nicolas Mora <mail@babelouest.org>
 * 
 * License AGPL
 * 
 */

import React from 'react';
import ReactDOM from 'react-dom';
import i18next from 'i18next';
import Backend from 'i18next-http-backend';
import LanguageDetector from 'i18next-browser-languagedetector';

import App from './Esras/App';

try {
  i18next
  .use(Backend)
  .use(LanguageDetector)
  .init({
    fallbackLng: 'en',
    ns: ['translations'],
    defaultNS: 'translations',
    backend: {
      loadPath: 'locales/{{lng}}/{{ns}}.json'
    }
  })
  .then(() => {
    ReactDOM.render(<App />, document.getElementById('root'));
  });
} catch (e) {
  $("#root").html('<div class="alert alert-danger" role="alert">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<span class="btn-icon-right">You must use a browser compatible with Esras</span>' +
                  '</div>');
}
