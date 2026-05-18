/*
 * Multi-select dropdown enhancement (#163 follow-up).
 *
 * Operator screenshot 2026-05-12 asked for a real multi-select widget
 * style — chips inline in a closed control, click to open a popup
 * with checkmark indicators + filterable list — instead of either
 * the chip-checkbox wall (too tall) or native <select multiple>
 * (Ctrl-click + visible scrollbox, uneven across OS).
 *
 * Progressive enhancement: works against any <select multiple>
 * carrying the `data-multiselect` attribute. If JS fails to load
 * for any reason, the native <select multiple> stays visible + the
 * form still submits — operator gets a degraded experience but
 * never a broken page.
 *
 * Form submission: state lives on the underlying <option selected>
 * attributes, so the server sees the same multi-value form field
 * shape (the existing provider_labels handler keeps working without
 * change). The widget keeps those in sync on every toggle.
 *
 * Keyboard:
 *   - Tab → focus the trigger button
 *   - Enter / Space on trigger → open popup, focus filter
 *   - Esc anywhere in widget → close popup, focus trigger
 *   - Arrow Up / Down on filter or list → move highlight
 *   - Enter on highlighted option → toggle selection
 *   - Click outside → close popup
 */

(function () {
  'use strict';

  var OPEN_ATTR = 'data-ms-open';

  function buildWidget(selectEl) {
    if (selectEl._msInited) return;
    selectEl._msInited = true;

    // Hide the native control but keep it focusable + form-bound.
    selectEl.style.display = 'none';

    var host = document.createElement('div');
    host.className = 'ms-host';
    host.setAttribute('data-ms-host', '');

    var trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'ms-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');

    var chips = document.createElement('span');
    chips.className = 'ms-chips';
    trigger.appendChild(chips);

    var placeholder = document.createElement('span');
    placeholder.className = 'ms-placeholder';
    placeholder.textContent =
      selectEl.getAttribute('data-placeholder') || 'None selected';
    trigger.appendChild(placeholder);

    var caret = document.createElement('span');
    caret.className = 'ms-caret';
    caret.setAttribute('aria-hidden', 'true');
    caret.textContent = '▾';
    trigger.appendChild(caret);

    var popup = document.createElement('div');
    popup.className = 'ms-popup';
    popup.hidden = true;
    popup.setAttribute('role', 'listbox');
    popup.setAttribute('aria-multiselectable', 'true');

    var filter = document.createElement('input');
    filter.type = 'text';
    filter.className = 'ms-filter';
    filter.placeholder = 'Filter…';
    filter.setAttribute('aria-label', 'Filter options');
    popup.appendChild(filter);

    var list = document.createElement('ul');
    list.className = 'ms-list';
    popup.appendChild(list);

    // Insert host after the native select. Hide select; keep it as
    // the source of truth for selected state.
    selectEl.parentNode.insertBefore(host, selectEl.nextSibling);
    host.appendChild(trigger);
    host.appendChild(popup);

    function renderChips() {
      chips.innerHTML = '';
      var anySelected = false;
      Array.prototype.forEach.call(selectEl.options, function (opt) {
        if (!opt.selected) return;
        anySelected = true;
        var chip = document.createElement('span');
        chip.className = 'ms-chip';
        var label = document.createElement('span');
        label.textContent = opt.textContent.trim();
        chip.appendChild(label);
        var x = document.createElement('button');
        x.type = 'button';
        x.className = 'ms-chip-x';
        x.setAttribute('aria-label', 'Remove ' + opt.textContent.trim());
        x.textContent = '×';
        x.addEventListener('click', function (ev) {
          ev.stopPropagation();
          opt.selected = false;
          fire(selectEl, 'change');
          renderChips();
          renderList();
        });
        chip.appendChild(x);
        chips.appendChild(chip);
      });
      placeholder.style.display = anySelected ? 'none' : '';
    }

    function renderList() {
      list.innerHTML = '';
      var needle = filter.value.trim().toLowerCase();
      var anyVisible = false;
      Array.prototype.forEach.call(selectEl.options, function (opt) {
        var label = opt.textContent.trim();
        if (needle && label.toLowerCase().indexOf(needle) === -1) return;
        anyVisible = true;
        var li = document.createElement('li');
        li.className = 'ms-option';
        li.setAttribute('role', 'option');
        li.setAttribute('aria-selected', opt.selected ? 'true' : 'false');
        li.tabIndex = -1;
        var check = document.createElement('span');
        check.className = 'ms-check';
        check.setAttribute('aria-hidden', 'true');
        check.textContent = opt.selected ? '✓' : ' ';
        li.appendChild(check);
        var text = document.createElement('span');
        text.className = 'ms-option-label';
        text.textContent = label;
        li.appendChild(text);
        li.addEventListener('click', function () {
          opt.selected = !opt.selected;
          fire(selectEl, 'change');
          renderChips();
          renderList();
          filter.focus();
        });
        list.appendChild(li);
      });
      if (!anyVisible) {
        var empty = document.createElement('li');
        empty.className = 'ms-empty';
        empty.textContent = 'No matches.';
        list.appendChild(empty);
      }
    }

    function open() {
      popup.hidden = false;
      host.setAttribute(OPEN_ATTR, '');
      trigger.setAttribute('aria-expanded', 'true');
      filter.value = '';
      renderList();
      filter.focus();
    }

    function close(focusTrigger) {
      popup.hidden = true;
      host.removeAttribute(OPEN_ATTR);
      trigger.setAttribute('aria-expanded', 'false');
      if (focusTrigger) trigger.focus();
    }

    function moveHighlight(delta) {
      var items = list.querySelectorAll('.ms-option');
      if (!items.length) return;
      var current = list.querySelector('.ms-highlight');
      var idx = current ? Array.prototype.indexOf.call(items, current) : -1;
      idx = (idx + delta + items.length) % items.length;
      items.forEach(function (it) { it.classList.remove('ms-highlight'); });
      items[idx].classList.add('ms-highlight');
      items[idx].scrollIntoView({ block: 'nearest' });
    }

    trigger.addEventListener('click', function (ev) {
      ev.preventDefault();
      if (popup.hidden) open();
      else close(true);
    });

    filter.addEventListener('input', renderList);

    filter.addEventListener('keydown', function (ev) {
      if (ev.key === 'ArrowDown') {
        ev.preventDefault();
        moveHighlight(1);
      } else if (ev.key === 'ArrowUp') {
        ev.preventDefault();
        moveHighlight(-1);
      } else if (ev.key === 'Enter') {
        ev.preventDefault();
        var hl = list.querySelector('.ms-highlight');
        if (hl) hl.click();
      } else if (ev.key === 'Escape') {
        ev.preventDefault();
        close(true);
      }
    });

    document.addEventListener('click', function (ev) {
      if (popup.hidden) return;
      if (host.contains(ev.target)) return;
      close(false);
    });

    document.addEventListener('keydown', function (ev) {
      if (popup.hidden) return;
      if (ev.key === 'Escape') {
        ev.preventDefault();
        close(true);
      }
    });

    renderChips();
  }

  function fire(el, name) {
    var ev;
    try {
      ev = new Event(name, { bubbles: true });
    } catch (e) {
      ev = document.createEvent('Event');
      ev.initEvent(name, true, true);
    }
    el.dispatchEvent(ev);
  }

  function initAll(root) {
    var scope = root || document;
    var sels = scope.querySelectorAll
      ? scope.querySelectorAll('select[multiple][data-multiselect]')
      : [];
    Array.prototype.forEach.call(sels, buildWidget);
  }

  // Initial pass on first paint.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { initAll(); });
  } else {
    initAll();
  }

  // HTMX swap support — re-init on any incoming fragment that
  // includes a multi-select. The rule editor uses inline-row swap
  // for Edit, so the picker arrives via HTMX, not page load.
  document.body && document.body.addEventListener('htmx:afterSwap', function (ev) {
    initAll(ev.target);
  });
})();
