import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const template = readFileSync(new URL('../templates/editor.html', import.meta.url), 'utf8');
process.env.TZ = 'Europe/Berlin';

function productionScheduleFunctions() {
  const start = template.indexOf('    function localInputValue(date) {');
  const end = template.indexOf('    // ---- Write / Preview tabs', start);
  assert.notEqual(start, -1, 'production schedule functions exist');
  assert.notEqual(end, -1, 'production schedule boundary exists');
  return template.slice(start, end);
}

function productionRecoveryFunctions() {
  const start = template.indexOf('    function snapshot() {');
  const end = template.indexOf('    function differsFromForm(d) {', start);
  assert.notEqual(start, -1, 'production snapshot function exists');
  assert.notEqual(end, -1, 'production apply boundary exists');
  return template.slice(start, end);
}

function productionServerAutosaveFunction() {
  const start = template.indexOf('    function persistServerAutosave() {');
  const end = template.indexOf('    function scheduleAutosave() {', start);
  assert.notEqual(start, -1, 'production server autosave function exists');
  assert.notEqual(end, -1, 'production server autosave boundary exists');
  return template.slice(start, end);
}

function productionClientSequenceInitialization() {
  const start = template.indexOf('    var initialClientSeq =');
  const end = template.indexOf('    function persistRecovery(', start);
  assert.notEqual(start, -1, 'production client sequence initialization exists');
  assert.notEqual(end, -1, 'production client sequence boundary exists');
  return template.slice(start, end);
}

function productionConflictFunctions() {
  const start = template.indexOf('    function showServerRecoveryLink(');
  const end = template.indexOf('    function syncCover()', start);
  assert.notEqual(start, -1, 'production recovery-link function exists');
  assert.notEqual(end, -1, 'production recovery-link boundary exists');
  return template.slice(start, end);
}

function input(value = '') {
  return {
    value,
    checked: false,
    events: [],
    dispatchEvent(event) { this.events.push(event.type); },
  };
}

test('Writer recovery executes metadata snapshot then restores every field', () => {
  const fields = {
    title: input('Recovered title'),
    body: input('Recovered body'),
    tags: input('rust, recovery'),
    cover: input('https://drive.w33d.xyz/s/cover_recovery'),
    customExcerpt: input('Recovered custom excerpt'),
    metaTitle: input('Recovered search title'),
    metaDescription: input('Recovered search description'),
    canonicalUrl: input('https://example.com/recovered-canonical'),
    socialTitle: input('Recovered social title'),
    socialDescription: input('Recovered social description'),
    socialImage: input('https://drive.w33d.xyz/s/social_recovery'),
    publishAt: input('2026-07-12T10:30'),
    publishAtEpoch: input('1783845000'),
    pinned: input(),
  };
  fields.pinned.checked = true;

  const document = {
    getElementById(id) {
      if (id === 'publish_at') { return fields.publishAt; }
      if (id === 'publish_at_epoch') { return fields.publishAtEpoch; }
      return null;
    },
  };
  const form = {
    querySelector(selector) {
      return selector === 'input[name="pinned"]' ? fields.pinned : null;
    },
  };
  let coverSyncs = 0;
  let socialSyncs = 0;
  class TestEvent {
    constructor(type) { this.type = type; }
  }

  const build = new Function(
    'titleEl',
    'bodyEl',
    'tagsEl',
    'coverEl',
    'customExcerptEl',
    'metaTitleEl',
    'metaDescriptionEl',
    'canonicalUrlEl',
    'socialTitleEl',
    'socialDescriptionEl',
    'socialImageEl',
    'document',
    'form',
    'Event',
    'syncCover',
    'syncSocialPreview',
    'restoreExactSchedule',
    `${productionRecoveryFunctions()}\nreturn { snapshot, apply };`,
  );
  const recovery = build(
    fields.title,
    fields.body,
    fields.tags,
    fields.cover,
    fields.customExcerpt,
    fields.metaTitle,
    fields.metaDescription,
    fields.canonicalUrl,
    fields.socialTitle,
    fields.socialDescription,
    fields.socialImage,
    document,
    form,
    TestEvent,
    () => { coverSyncs += 1; },
    () => { socialSyncs += 1; },
    (epoch) => {
      if (fields.publishAt.value !== '2026-07-12T10:30') { return false; }
      fields.publishAtEpoch.value = epoch;
      return true;
    },
  );

  const saved = recovery.snapshot();
  assert.deepEqual(
    {
      customExcerpt: saved.customExcerpt,
      metaTitle: saved.metaTitle,
      metaDescription: saved.metaDescription,
      canonicalUrl: saved.canonicalUrl,
      socialTitle: saved.socialTitle,
      socialDescription: saved.socialDescription,
      socialImage: saved.socialImage,
      publishAtEpoch: saved.publishAtEpoch,
    },
    {
      customExcerpt: 'Recovered custom excerpt',
      metaTitle: 'Recovered search title',
      metaDescription: 'Recovered search description',
      canonicalUrl: 'https://example.com/recovered-canonical',
      socialTitle: 'Recovered social title',
      socialDescription: 'Recovered social description',
      socialImage: 'https://drive.w33d.xyz/s/social_recovery',
      publishAtEpoch: '1783845000',
    },
  );

  for (const field of Object.values(fields)) {
    field.value = '';
    field.checked = false;
  }
  recovery.apply(saved);

  assert.equal(fields.title.value, 'Recovered title');
  assert.equal(fields.body.value, 'Recovered body');
  assert.equal(fields.tags.value, 'rust, recovery');
  assert.equal(fields.cover.value, 'https://drive.w33d.xyz/s/cover_recovery');
  assert.equal(fields.customExcerpt.value, 'Recovered custom excerpt');
  assert.equal(fields.metaTitle.value, 'Recovered search title');
  assert.equal(fields.metaDescription.value, 'Recovered search description');
  assert.equal(fields.canonicalUrl.value, 'https://example.com/recovered-canonical');
  assert.equal(fields.socialTitle.value, 'Recovered social title');
  assert.equal(fields.socialDescription.value, 'Recovered social description');
  assert.equal(fields.socialImage.value, 'https://drive.w33d.xyz/s/social_recovery');
  assert.equal(fields.publishAt.value, '2026-07-12T10:30');
  assert.equal(fields.publishAtEpoch.value, '1783845000');
  assert.equal(fields.pinned.checked, true);
  assert.equal(coverSyncs, 1);
  assert.equal(socialSyncs, 1);
});

test('Writer preserves the second DST-fold epoch until the author changes wall time', () => {
  const secondFoldEpoch = Math.floor(Date.UTC(2026, 9, 25, 1, 30, 0) / 1000);
  const firstFoldEpoch = Math.floor(Date.UTC(2026, 9, 25, 0, 30, 0) / 1000);
  const listeners = {};
  const publishAt = {
    value: '',
    getAttribute(name) {
      if (name === 'data-utc-epoch') { return String(secondFoldEpoch); }
      if (name === 'data-utc-value') { return '2026-10-25T01:30'; }
      return '';
    },
    addEventListener(type, listener) { listeners[type] = listener; },
    dispatchEvent(event) { if (listeners[event.type]) { listeners[event.type](event); } },
  };
  const publishAtEpoch = input('');
  const scheduleTimezone = input('');
  const scheduleOffset = input('');
  const scheduleConfirm = { textContent: '' };
  const buildSchedule = new Function(
    'publishAtEl',
    'publishEpochEl',
    'scheduleTimezoneEl',
    'scheduleOffsetEl',
    'scheduleConfirm',
    'Intl',
    `${productionScheduleFunctions()}\nreturn { restoreExactSchedule, scheduleIsReady, syncSchedule };`,
  );
  const schedule = buildSchedule(
    publishAt,
    publishAtEpoch,
    scheduleTimezone,
    scheduleOffset,
    scheduleConfirm,
    globalThis.Intl,
  );

  assert.equal(publishAt.value, '2026-10-25T02:30');
  assert.equal(publishAtEpoch.value, String(secondFoldEpoch));
  assert.equal(scheduleOffset.value, '60', 'the second fold uses CET, not the first CEST offset');
  assert.match(scheduleConfirm.textContent, /UTC 2026-10-25T01:30:00Z/);
  assert.equal(schedule.scheduleIsReady(), true);
  assert.equal(
    publishAtEpoch.value,
    String(secondFoldEpoch),
    'submit validation keeps a matching exact epoch instead of reparsing the ambiguous wall time',
  );

  const document = {
    getElementById(id) {
      if (id === 'publish_at') { return publishAt; }
      if (id === 'publish_at_epoch') { return publishAtEpoch; }
      return null;
    },
  };
  const pinned = input();
  const form = {
    querySelector(selector) { return selector === 'input[name="pinned"]' ? pinned : null; },
  };
  const buildRecovery = new Function(
    'titleEl', 'bodyEl', 'tagsEl', 'coverEl', 'customExcerptEl', 'metaTitleEl',
    'metaDescriptionEl', 'canonicalUrlEl', 'socialTitleEl', 'socialDescriptionEl',
    'socialImageEl', 'document', 'form', 'Event', 'syncCover', 'syncSocialPreview',
    'restoreExactSchedule',
    `${productionRecoveryFunctions()}\nreturn { snapshot, apply };`,
  );
  const recovery = buildRecovery(
    null, null, null, null, null, null, null, null, null, null, null,
    document,
    form,
    class TestEvent { constructor(type) { this.type = type; } },
    () => {},
    () => {},
    schedule.restoreExactSchedule,
  );
  const saved = recovery.snapshot();
  assert.equal(saved.publishAtEpoch, String(secondFoldEpoch));
  publishAtEpoch.value = '';
  recovery.apply(saved);
  assert.equal(
    publishAtEpoch.value,
    String(secondFoldEpoch),
    'local recovery keeps the exact epoch when its wall time still matches',
  );

  listeners.input();
  assert.equal(
    publishAtEpoch.value,
    String(firstFoldEpoch),
    'only an author input event reparses the ambiguous wall time using the browser default fold',
  );
});

test('Writer server autosave emits monotonic client sequences and surfaces 409', async () => {
  class TestFormData {
    forEach(callback) {
      callback('csrf', 'csrf_token');
      callback('session', 'autosave_session');
      callback('1', 'expected_version');
    }
  }
  const build = new Function(
    'autosaveUrl',
    'window',
    'clientSeqEl',
    'URLSearchParams',
    'FormData',
    'form',
    'fetch',
    'setStatus',
    'hfToast',
    'initialServerClientSeq',
    'conflictErrorFromResponse',
    'showServerRecoveryLink',
    `var serverClientSeq = initialServerClientSeq;\n${productionServerAutosaveFunction()}\nreturn persistServerAutosave;`,
  );

  const calls = [];
  const clientSeqEl = { value: '0' };
  const persist = build(
    '/api/writer/autosave/post',
    { fetch: true },
    clientSeqEl,
    URLSearchParams,
    TestFormData,
    {},
    async (_url, options) => {
      calls.push(new URLSearchParams(options.body).get('client_seq'));
      return { status: 200, ok: true, async json() { return { ok: true }; } };
    },
    () => {},
    () => {},
    0,
    (response, label) => response.json().then((data) => {
      const error = new Error(label);
      error.conflict = true;
      error.recover = data.recover;
      throw error;
    }),
    () => {},
  );
  persist();
  persist();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(calls, ['1', '2']);
  assert.equal(clientSeqEl.value, '2');

  const states = [];
  const toasts = [];
  const conflict = build(
    '/api/writer/autosave/post',
    { fetch: true },
    { value: '0' },
    URLSearchParams,
    TestFormData,
    {},
    async () => ({ status: 409, ok: false, async json() { return {}; } }),
    (...args) => states.push(args),
    (...args) => toasts.push(args),
    0,
    (response, label) => response.json().then((data) => {
      const error = new Error(label);
      error.conflict = true;
      error.recover = data.recover;
      throw error;
    }),
    () => {},
  );
  conflict();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(states, [['error', 'Conflict · Newer server version']]);
  assert.equal(toasts.length, 1);

  const resumedCalls = [];
  const resumed = build(
    '/api/writer/autosave/post',
    { fetch: true },
    { value: '7' },
    URLSearchParams,
    TestFormData,
    {},
    async (_url, options) => {
      resumedCalls.push(new URLSearchParams(options.body).get('client_seq'));
      return { status: 200, ok: true, async json() { return { ok: true }; } };
    },
    () => {},
    () => {},
    7,
    () => {},
    () => {},
  );
  resumed();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(resumedCalls, ['8'], 'recovered editor resumes after the persisted sequence');
});

test('Writer initializes recovered sequences safely and exposes a parsed 409 recovery URL', async () => {
  const initialize = new Function(
    'clientSeqEl',
    `${productionClientSequenceInitialization()}\nreturn serverClientSeq;`,
  );
  assert.equal(initialize({ value: '7' }), 7);
  assert.equal(initialize({ value: '-1' }), 0);
  assert.equal(initialize({ value: '9007199254740992' }), 0);
  assert.equal(initialize({ value: 'not-a-number' }), 0);

  const link = {
    hidden: true,
    href: '',
    setAttribute(name, value) { if (name === 'href') { this.href = value; } },
  };
  const bar = { hidden: true };
  const message = { textContent: '' };
  const document = {
    getElementById(id) {
      if (id === 'draftbar') { return bar; }
      if (id === 'draftbar-msg') { return message; }
      return null;
    },
  };
  const build = new Function(
    'serverRecoveryLink',
    'document',
    `${productionConflictFunctions()}\nreturn { showServerRecoveryLink, conflictErrorFromResponse };`,
  );
  const helpers = build(link, document);
  const recover = '/edit/durable-story?recover=private-session';
  const error = await helpers.conflictErrorFromResponse(
    { async json() { return { recover }; } },
    'save conflict',
  ).catch((caught) => caught);
  assert.equal(error.conflict, true);
  assert.equal(error.recover, recover);

  helpers.showServerRecoveryLink(error.recover);
  assert.equal(link.href, recover);
  assert.equal(link.hidden, false);
  assert.equal(bar.hidden, false);
  assert.match(message.textContent, /private server recovery copy/i);
});

test('Writer preflight keeps native SSR navigation and a recovery backup', () => {
  assert.match(template, /formaction="\{\{REVIEW_ACTION\}\}" data-review-submit/);
  assert.match(template, /name="schedule_timezone"/);
  assert.match(template, /name="schedule_offset_minutes"/);
  assert.match(template, /data-utc-epoch="\{\{PUBLISH_AT_EPOCH\}\}"/);
  assert.match(template, /id="publish_at_epoch" name="publish_at_epoch" value=""/);

  const start = template.indexOf("    form.addEventListener('submit'");
  const end = template.indexOf('  })();', start);
  assert.notEqual(start, -1, 'production submit state machine exists');
  const submit = template.slice(start, end);
  const backup = submit.indexOf('localStorage.setItem(bakKey');
  const review = submit.indexOf("submitter.hasAttribute('data-review-submit')");
  const ajax = submit.indexOf('event.preventDefault();', review);
  assert(backup >= 0 && backup < review, 'review navigation first snapshots the complete draft');
  assert(review >= 0 && review < ajax, 'review returns to native form navigation before AJAX save');
  assert.match(submit, /setStatus\('saving', 'Preparing review\\u2026'\);\s*return;/);
});
