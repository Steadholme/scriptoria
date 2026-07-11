(function () {
  "use strict";

  var root = document.querySelector("[data-ap-share-room]");
  if (!root) { return; }

  function copyControls() {
    var buttons = root.querySelectorAll(".copy-btn");
    Array.prototype.forEach.call(buttons, function (button) {
      button.addEventListener("click", function () {
        var row = button.closest ? button.closest(".embed-box__row") : button.parentNode;
        var input = row && row.querySelector(button.getAttribute("data-copy") || ".embed-box__input");
        if (!input) { return; }
        var original = button.getAttribute("data-label") || button.textContent;
        function done() {
          button.textContent = "Copied";
          window.setTimeout(function () { button.textContent = original; }, 1200);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(input.value).then(done, function () {
            input.select();
            if (document.execCommand("copy")) { done(); }
          });
        } else {
          input.select();
          if (document.execCommand("copy")) { done(); }
        }
      });
    });
  }

  function imagePreview() {
    var dialog = root.querySelector("[data-share-dialog]");
    var image = dialog && dialog.querySelector("[data-share-dialog-image]");
    var closeButtons = dialog && dialog.querySelectorAll("[data-share-dialog-close]");
    var previousFocus = null;
    if (!dialog || !image) { return; }

    function close() {
      dialog.hidden = true;
      image.removeAttribute("src");
      image.alt = "";
      if (previousFocus && previousFocus.focus) { previousFocus.focus(); }
    }

    root.addEventListener("click", function (event) {
      var trigger = event.target.closest && event.target.closest("[data-share-preview]");
      if (!trigger) { return; }
      event.preventDefault();
      previousFocus = trigger;
      image.src = trigger.getAttribute("data-share-preview") || "";
      image.alt = trigger.getAttribute("data-share-preview-name") || "Shared image preview";
      dialog.hidden = false;
      var closeButton = dialog.querySelector(".sr-dialog__close");
      if (closeButton) { closeButton.focus(); }
    });
    Array.prototype.forEach.call(closeButtons, function (button) { button.addEventListener("click", close); });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && !dialog.hidden) { close(); }
    });
  }

  function uploadQueue() {
    var form = root.querySelector("[data-upload-form]");
    var input = form && form.querySelector("input[type=file]");
    var queue = root.querySelector("[data-upload-queue]");
    var list = queue && queue.querySelector("[data-upload-list]");
    var summary = root.querySelector("[data-upload-summary]");
    var csrf = form && form.querySelector("input[name=csrf_token]");
    if (!form || !input || !queue || !list || !csrf || !window.FormData || !window.XMLHttpRequest) { return; }

    // The server/no-JS contract intentionally accepts one file. Multiple selection is enabled only
    // after this queue owns submission and sends one existing POST per item.
    input.multiple = true;
    form.setAttribute("data-upload-enhanced", "true");
    var items = [];
    var running = false;

    function size(bytes) {
      if (bytes < 1024) { return bytes + " B"; }
      if (bytes < 1024 * 1024) { return (bytes / 1024).toFixed(1) + " KB"; }
      return (bytes / (1024 * 1024)).toFixed(1) + " MB";
    }

    function announce(message) {
      if (summary) { summary.textContent = message; }
    }

    function render(item) {
      var row = document.createElement("li");
      var info = document.createElement("div");
      var name = document.createElement("span");
      var meta = document.createElement("span");
      var state = document.createElement("span");
      var progress = document.createElement("progress");
      row.className = "sr-queue__item";
      name.className = "sr-queue__name";
      meta.className = "sr-file-row__meta";
      state.className = "sr-queue__state";
      progress.className = "sr-queue__progress";
      progress.max = 100;
      progress.value = 0;
      name.textContent = item.file.name;
      meta.textContent = size(item.file.size);
      state.textContent = "Queued";
      info.appendChild(name);
      info.appendChild(meta);
      row.appendChild(info);
      row.appendChild(state);
      row.appendChild(progress);
      list.appendChild(row);
      item.row = row;
      item.state = state;
      item.progress = progress;
    }

    function send(item) {
      return new Promise(function (resolve) {
        var data = new FormData();
        data.append("csrf_token", csrf.value);
        data.append("file", item.file, item.file.name);
        var xhr = new XMLHttpRequest();
        item.status = "uploading";
        item.row.className = "sr-queue__item is-uploading";
        item.state.textContent = "Uploading";
        xhr.open("POST", form.action, true);
        xhr.setRequestHeader("Accept", "text/html");
        if (xhr.upload) {
          xhr.upload.addEventListener("progress", function (event) {
            if (!event.lengthComputable) { return; }
            var percent = Math.round((event.loaded / event.total) * 100);
            item.progress.value = percent;
            item.state.textContent = percent + "%";
          });
        }
        xhr.addEventListener("load", function () {
          if (xhr.status >= 200 && xhr.status < 300) {
            item.status = "done";
            item.row.className = "sr-queue__item is-done";
            item.progress.value = 100;
            item.state.textContent = "Uploaded";
          } else {
            item.status = "error";
            item.row.className = "sr-queue__item is-error";
            item.progress.value = 100;
            item.state.textContent = "Failed";
            addRetry(item);
          }
          resolve();
        });
        xhr.addEventListener("error", function () {
          item.status = "error";
          item.row.className = "sr-queue__item is-error";
          item.progress.value = 100;
          item.state.textContent = "Network error";
          addRetry(item);
          resolve();
        });
        xhr.send(data);
      });
    }

    function addRetry(item) {
      if (item.retry) { return; }
      var retry = document.createElement("button");
      retry.type = "button";
      retry.className = "sr-retry";
      retry.textContent = "Retry";
      retry.addEventListener("click", function () {
        retry.remove();
        item.retry = null;
        item.status = "queued";
        item.state.textContent = "Queued";
        item.progress.value = 0;
        run();
      });
      item.retry = retry;
      item.row.appendChild(retry);
    }

    async function run() {
      if (running) { return; }
      running = true;
      var item;
      while ((item = items.find(function (candidate) { return candidate.status === "queued"; }))) {
        await send(item);
      }
      running = false;
      var done = items.filter(function (candidate) { return candidate.status === "done"; }).length;
      var failed = items.filter(function (candidate) { return candidate.status === "error"; }).length;
      if (failed) { announce(done + " uploaded, " + failed + " need attention."); }
      else if (done) { announce(done + (done === 1 ? " file uploaded." : " files uploaded.")); }
    }

    function enqueue(fileList) {
      Array.prototype.forEach.call(fileList || [], function (file) {
        var item = { file: file, status: "queued", row: null, state: null, progress: null, retry: null };
        items.push(item);
        render(item);
      });
      if (items.length) {
        queue.hidden = false;
        announce(items.length + (items.length === 1 ? " file ready." : " files ready."));
        run();
      }
    }

    input.addEventListener("change", function () {
      enqueue(input.files);
      input.value = "";
    });
    form.addEventListener("submit", function (event) {
      // With enhancement active, selection immediately enters the queue. Keep an empty submit inert.
      event.preventDefault();
      if (input.files && input.files.length) { enqueue(input.files); input.value = ""; }
    });
    ["dragenter", "dragover"].forEach(function (name) {
      form.addEventListener(name, function (event) { event.preventDefault(); form.classList.add("is-over"); });
    });
    ["dragleave", "drop"].forEach(function (name) {
      form.addEventListener(name, function (event) { event.preventDefault(); form.classList.remove("is-over"); });
    });
    form.addEventListener("drop", function (event) {
      if (event.dataTransfer && event.dataTransfer.files) { enqueue(event.dataTransfer.files); }
    });
  }

  copyControls();
  imagePreview();
  uploadQueue();
}());
