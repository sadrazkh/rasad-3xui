'use strict';
// Exercise the production request functions with controlled network responses.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '..', 'dist', 'app.js'), 'utf8');
function between(start, end) {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `Missing production function: ${start}`);
  return source.slice(from, to);
}
const production = [
  source.match(/^let loadVersion=.*;$/m)[0],
  between('async function api(', '\nfunction load('),
  between('function load(', '\nfunction audit('),
  between('function csvCell(', '\nfunction loginScreen('),
  between('function loginScreen(', '\ndocument.addEventListener('),
  between("document.addEventListener('click',", "\ndocument.addEventListener('input',"),
].join('\n');

const flush = () => new Promise(resolve => setImmediate(resolve));
function harness() {
  const requests = [], renders = [], messages = [], downloads = [], toggles = [];
  const app = {innerHTML: ''}, listeners = {};
  const state = {mode: 'live', period: 'today', user: 'first@example.test',
                 csrf: 'first-session', report: null, reportSelection: null, busy: false,
                 query: '', filter: 'all'};
  const context = {
    state,
    fetch(url) {
      return new Promise((resolve, reject) => {
        requests.push({
          url,
          succeed(report) {resolve({status: 200, ok: true, json: async () => report});},
          unauthorized() {resolve({status: 401, ok: false});},
          fail: reject,
        });
      });
    },
    render() {
      renders.push({period: state.period, user: state.user, report: state.report});
      app.innerHTML = 'dashboard';
    },
    toast(message) {messages.push(message);},
    download(content, type, name) {downloads.push({content, type, name});},
    confirmMonitoring(email, enabled) {toggles.push({email, enabled});},
    document: {addEventListener(name, listener) {listeners[name] = listener;}},
    $(selector) {return selector === '#app' ? app : app.innerHTML.includes('class="login"') ? {} : null;},
    icon() {return '';},
  };
  vm.createContext(context);
  vm.runInContext(production, context, {filename: 'production-app-functions.js'});
  return {state, requests, renders, messages, downloads, toggles, app,
          load: context.load, loginScreen: context.loginScreen,
          click(action, email) {
            const button = {dataset: {action, email}, matches() {return false;}};
            return listeners.click({target: {closest() {return button;}}});
          }};
}

async function latestSelectionWins() {
  const h = harness(), first = h.load();
  await flush();
  assert.equal(h.requests[0].url, '/api/report?period=today&email=first%40example.test');
  h.state.period = 'yesterday';
  h.state.user = 'intermediate@example.test';
  const intermediate = h.load();
  h.state.period = 'week';
  h.state.user = 'latest@example.test';
  const latest = h.load();
  assert.equal(first, intermediate);
  assert.equal(first, latest);
  assert.equal(h.requests.length, 1, 'Only one request should run at a time');
  h.requests[0].succeed({period: 'today', domains: [{domain: 'old-user.example'}]});
  await flush();
  assert.equal(h.renders.length, 0, 'Never show the old response under the new selection');
  assert.equal(h.state.report, null);
  assert.equal(h.requests.length, 2);
  assert.equal(h.requests[1].url, '/api/report?period=week&email=latest%40example.test');
  const report = {period: 'week', domains: [{domain: 'latest-user.example'}]};
  h.requests[1].succeed(report);
  await Promise.all([first, intermediate, latest]);
  assert.deepEqual(h.renders, [{period: 'week', user: 'latest@example.test', report}]);
  assert.equal(h.state.busy, false);
}

async function staleFailureDoesNotReplaceLatestSelection() {
  const h = harness(), first = h.load();
  await flush();
  h.state.period = 'yesterday';
  h.state.user = null;
  const latest = h.load();
  h.requests[0].fail(new Error('old request failed'));
  await flush();
  assert.equal(h.messages.length, 0, 'An obsolete failure must not replace the latest view');
  assert.equal(h.requests[1].url, '/api/report?period=yesterday');
  h.requests[1].succeed({period: 'yesterday', domains: []});
  await Promise.all([first, latest]);
  assert.equal(h.renders.length, 1);
  assert.equal(h.renders[0].period, 'yesterday');
}

async function logoutInvalidatesPendingReport() {
  const h = harness(), pending = h.load();
  await flush();
  h.loginScreen();
  h.requests[0].succeed({period: 'today', domains: [{domain: 'private.example'}]});
  await pending;
  assert.equal(h.renders.length, 0, 'A response must not restore the dashboard after logout');
  assert.equal(h.state.report, null);
  assert.equal(h.state.csrf, '');
  assert.match(h.app.innerHTML, /id="login-form"/);
  assert.equal(h.requests.length, 1, 'Logout must not queue another protected request');
}

async function oldUnauthorizedResponseDoesNotDiscardNewLogin() {
  const h = harness(), pending = h.load();
  await flush();
  h.loginScreen();
  h.state.csrf = 'new-session';
  h.state.user = 'new@example.test';
  const newLogin = h.load();
  h.requests[0].unauthorized();
  await flush();
  assert.equal(h.state.csrf, 'new-session', 'An old 401 must not clear a newer session');
  assert.equal(h.requests[1].url, '/api/report?period=today&email=new%40example.test');
  h.requests[1].succeed({period: 'today', domains: []});
  await Promise.all([pending, newLogin]);
  assert.equal(h.renders.length, 1);
  assert.equal(h.renders[0].user, 'new@example.test');
  assert.equal(h.messages.length, 0);
}

async function refreshDuringRequestLoadsAgain() {
  const h = harness(), first = h.load();
  await flush();
  const refresh = h.load();
  h.requests[0].succeed({period: 'today', version: 'before-refresh'});
  await flush();
  assert.equal(h.renders.length, 0);
  assert.equal(h.requests.length, 2, 'A refresh after a mutation must not be dropped');
  h.requests[1].succeed({period: 'today', version: 'after-refresh'});
  await Promise.all([first, refresh]);
  assert.equal(h.renders[0].report.version, 'after-refresh');
}

async function selectionChangeInvalidatesCachedExportsAndToggles() {
  const h = harness(), initial = h.load();
  await flush();
  const cached = {period: 'today', users: [], domains: [{domain: 'cached.example', connections: 2, last: 1}]};
  h.requests[0].succeed(cached);
  await initial;
  const refresh = h.load();
  assert.equal(h.state.report, cached, 'Refreshing the same selection should retain its valid cache');
  await flush();
  h.state.period = 'yesterday';
  h.state.user = 'next@example.test';
  const changed = h.load();
  assert.equal(h.state.report, null, 'Changing selection must invalidate cache synchronously');
  assert.equal(h.state.reportSelection, null);
  await h.click('export-users');
  await h.click('export-domains');
  await h.click('export-json');
  await h.click('monitor-user', 'first@example.test');
  assert.equal(h.downloads.length, 0, 'No cached CSV or JSON may escape under the new selection');
  assert.equal(h.toggles.length, 0, 'No user toggle may use a missing report');
  assert.equal(h.messages.length, 4);
  assert.ok(h.messages.every(message => message.includes('کمی صبر کنید')));
  h.requests[1].succeed(cached);
  await flush();
  assert.equal(h.state.report, null, 'The pending old refresh must not restore its cache');
  assert.equal(h.requests[2].url, '/api/report?period=yesterday&email=next%40example.test');
  const current = {period: 'yesterday', users: [], domains: [{domain: 'current.example', connections: 3, last: 2}]};
  h.requests[2].succeed(current);
  await Promise.all([refresh, changed]);
  await h.click('export-domains');
  await h.click('export-json');
  assert.equal(h.downloads.length, 2);
  assert.match(h.downloads[0].name, /yesterday/);
  assert.match(h.downloads[0].content, /current\.example/);
  assert.doesNotMatch(h.downloads[0].content, /cached\.example/);
  assert.deepEqual(JSON.parse(h.downloads[1].content), current);
}

test('latest user and period win; stale response is discarded', latestSelectionWins);
test('stale failure is ignored and the latest selection still loads', staleFailureDoesNotReplaceLatestSelection);
test('logout discards the pending report and keeps the login screen', logoutInvalidatesPendingReport);
test('old unauthorized response cannot clear a newer login', oldUnauthorizedResponseDoesNotDiscardNewLogin);
test('refresh during an active request gets a new response', refreshDuringRequestLoadsAgain);
test('selection change invalidates cached exports and user toggles until the new report arrives', selectionChangeInvalidatesCachedExportsAndToggles);
