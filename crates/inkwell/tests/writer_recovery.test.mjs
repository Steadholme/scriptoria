import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const template = readFileSync(new URL('../templates/editor.html', import.meta.url), 'utf8');

function productionRecoveryFunctions() {
  const start = template.indexOf('    function snapshot() {');
  const end = template.indexOf('    function differsFromForm(d) {', start);
  assert.notEqual(start, -1, 'production snapshot function exists');
  assert.notEqual(end, -1, 'production apply boundary exists');
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
    pinned: input(),
  };
  fields.pinned.checked = true;

  const document = {
    getElementById(id) {
      return id === 'publish_at' ? fields.publishAt : null;
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
    },
    {
      customExcerpt: 'Recovered custom excerpt',
      metaTitle: 'Recovered search title',
      metaDescription: 'Recovered search description',
      canonicalUrl: 'https://example.com/recovered-canonical',
      socialTitle: 'Recovered social title',
      socialDescription: 'Recovered social description',
      socialImage: 'https://drive.w33d.xyz/s/social_recovery',
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
  assert.equal(fields.pinned.checked, true);
  assert.equal(coverSyncs, 1);
  assert.equal(socialSyncs, 1);
});
