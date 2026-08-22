(() => {
  "use strict";

  const MAX_TEXT_CHARACTERS = 20000;
  const MAX_BROWSER_FILE_BYTES = 200 * 1024 * 1024;
  const API_BASE = (window.WATERMARKS_API_BASE || "/api").replace(/\/+$/, "");
  const I18N = window.REMOVE_WATERMARK_I18N || {};
  const SUPPORTED_LOCALES = Object.keys(I18N);
  const SUPPORTED_THEMES = ["dark", "light", "midnight", "forest", "violet"];
  const LOCAL_REMOVABLE_MARKS = new Map([
    [0x00ad, "U+00AD SOFT HYPHEN"],
    [0x200b, "U+200B ZERO WIDTH SPACE"],
    [0xfeff, "U+FEFF ZERO WIDTH NO-BREAK SPACE / BOM"],
  ]);

  const state = {
    attachment: null,
    busy: false,
    backendAvailable: null,
    previewUrl: null,
    locale: "zh-CN",
    theme: "dark",
    serviceState: "checking",
    outputModel: null,
  };

  try {
    const storedLocale = window.localStorage.getItem("remove-watermark-locale");
    const storedTheme = window.localStorage.getItem("remove-watermark-theme");
    if (SUPPORTED_LOCALES.includes(storedLocale)) state.locale = storedLocale;
    if (SUPPORTED_THEMES.includes(storedTheme)) state.theme = storedTheme;
  } catch {
    // Private browsing can disable localStorage; the default settings still work.
  }

  const $ = (id) => document.getElementById(id);
  const cleanerCard = $("cleaner-card");
  const textInput = $("text-input");
  const characterCount = $("character-count");
  const attachmentInput = $("attachment-input");
  const attachButton = $("attach-button");
  const attachmentDropzone = $("attachment-dropzone");
  const attachmentPreview = $("attachment-preview");
  const attachmentIcon = $("attachment-icon");
  const attachmentName = $("attachment-name");
  const attachmentRemove = $("attachment-remove");
  const textNfkc = $("text-nfkc");
  const scanButton = $("scan-button");
  const submitButton = $("submit-button");
  const submitHint = $("submit-hint");
  const serviceStatus = $("service-status");
  const serviceStatusText = $("service-status-text");
  const outputPanel = $("output-panel");
  const outputPlaceholder = $("output-placeholder");
  const outputLoading = $("output-loading");
  const outputContent = $("output-content");
  const outputState = $("output-state");
  const analysisOutput = $("analysis-output");
  const analysisTag = $("analysis-tag");
  const correctedOutput = $("corrected-output");
  const copyButton = $("copy-button");
  const fileResult = $("file-result");
  const errorBanner = $("error-banner");
  const languageSelect = $("language-select");
  const themeSelect = $("theme-select");
  const themeColor = $("theme-color");
  const backToTop = $("back-to-top");

  function t(key, values) {
    const dictionary = I18N[state.locale] || I18N["zh-CN"] || {};
    const fallback = I18N["zh-CN"] || {};
    let value = dictionary[key] || fallback[key] || key;
    if (values) {
      value = value.replace(/\{(\w+)\}/g, (match, name) => (
        Object.prototype.hasOwnProperty.call(values, name) ? values[name] : match
      ));
    }
    return value;
  }

  function applyLanguage(locale) {
    if (!SUPPORTED_LOCALES.includes(locale)) locale = "zh-CN";
    state.locale = locale;
    document.documentElement.lang = locale;
    document.documentElement.dir = locale === "ar" ? "rtl" : "ltr";
    if (languageSelect) languageSelect.value = locale;

    document.querySelectorAll("[data-i18n]").forEach((element) => {
      element.textContent = t(element.dataset.i18n);
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
      element.placeholder = t(element.dataset.i18nPlaceholder);
    });
    document.querySelectorAll("[data-i18n-aria-label]").forEach((element) => {
      element.setAttribute("aria-label", t(element.dataset.i18nAriaLabel));
    });
    if (themeSelect) {
      themeSelect.querySelectorAll("[data-i18n]").forEach((option) => {
        option.textContent = t(option.dataset.i18n);
      });
    }
    updateCharacterCount();
    updateSubmitState();
    if (state.serviceState) setServiceStatus(state.serviceState);
    if (outputState.dataset.i18nKey) outputState.textContent = t(outputState.dataset.i18nKey);
    if (state.outputModel) {
      analysisOutput.textContent = analysisText(
        state.outputModel.report,
        state.outputModel.detection,
      );
      if (state.outputModel.correctedKey) {
        correctedOutput.textContent = t(state.outputModel.correctedKey);
      }
      if (state.outputModel.analysisTagKey) {
        analysisTag.textContent = t(state.outputModel.analysisTagKey);
      }
    }
  }

  function applyTheme(theme) {
    if (!SUPPORTED_THEMES.includes(theme)) theme = "dark";
    state.theme = theme;
    document.documentElement.dataset.theme = theme;
    if (themeSelect) themeSelect.value = theme;
    const colors = {
      dark: "#050505",
      light: "#f4f6fb",
      midnight: "#07111f",
      forest: "#07110c",
      violet: "#100918",
    };
    if (themeColor) themeColor.content = colors[theme];
  }

  function setServiceStatus(stateName, text) {
    state.serviceState = stateName;
    serviceStatus.dataset.state = stateName;
    serviceStatusText.textContent = text || t(
      stateName === "ready" ? "service_online" : stateName === "error" ? "service_error" : "service_checking",
    );
  }

  function setError(message) {
    errorBanner.textContent = message || t("processing_failed");
    errorBanner.hidden = !message;
  }

  function setOutputState(stateName, text) {
    const labels = {
      waiting: "output_waiting",
      busy: "output_processing",
      error: "output_error",
      local_scan: "state_local_scan",
      scan: "state_scan_done",
      local_clean: "state_local_done",
      clean: "state_clean_done",
    };
    const key = text || labels[stateName] || stateName;
    outputState.dataset.state = stateName;
    outputState.dataset.i18nKey = key;
    outputState.textContent = t(key);
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    const units = ["KB", "MB", "GB"];
    let value = bytes;
    let unit = -1;
    do {
      value /= 1024;
      unit += 1;
    } while (value >= 1024 && unit < units.length - 1);
    return value.toFixed(value >= 10 ? 0 : 1) + " " + units[unit];
  }

  function extension(filename) {
    const match = filename.toLowerCase().match(/\.([a-z0-9]{1,8})$/);
    return match ? match[1] : "file";
  }

  function isTextFile(file) {
    const mime = file && file.type ? file.type : "";
    return Boolean(file && (
      mime.startsWith("text/")
      || /\.(txt|md|markdown|csv|json|xml|html|htm|yml|yaml|log|srt|vtt)$/i.test(file.name)
    ));
  }

  function isImageFile(file) {
    const mime = file && file.type ? file.type : "";
    return mime.startsWith("image/") || /\.(png|jpe?g|webp|gif|bmp|tiff?|avif|heic|heif)$/i.test(file.name);
  }

  function isVideoFile(file) {
    const mime = file && file.type ? file.type : "";
    return mime.startsWith("video/") || /\.(mp4|mov|webm|m4v|avi|mkv)$/i.test(file.name);
  }

  function isAudioFile(file) {
    const mime = file && file.type ? file.type : "";
    return mime.startsWith("audio/") || /\.(mp3|wav|m4a|aac|ogg|oga|flac|aiff?|opus)$/i.test(file.name);
  }

  function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  function base64ToText(base64) {
    return new TextDecoder().decode(base64ToBytes(base64));
  }

  function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }
    return btoa(binary);
  }

  async function request(path, payload) {
    let response;
    try {
      response = await fetch(API_BASE + path, {
        method: payload ? "POST" : "GET",
        headers: payload ? { "Content-Type": "application/json" } : undefined,
        body: payload ? JSON.stringify(payload) : undefined,
      });
    } catch (error) {
      error.status = 503;
      error.message = "backend unavailable";
      throw error;
    }

    let body;
    try {
      body = await response.json();
    } catch {
      body = {};
    }
    if (!response.ok || body.ok === false) {
      const error = new Error(body.error || t("http_error", { status: response.status }));
      error.status = response.status;
      throw error;
    }
    return body;
  }

  function isBackendUnavailable(error) {
    return error && (
      error.status === 502
      || error.status === 503
      || error.message === "backend unavailable"
      || error.message === "backend is not configured"
    );
  }

  function cleanOptions() {
    return textNfkc.checked ? { nfkc: true } : {};
  }

  function localTextReport(value) {
    const counts = new Map();
    for (const character of value) {
      const codepoint = character.codePointAt(0);
      const label = LOCAL_REMOVABLE_MARKS.get(codepoint);
      if (!label) continue;
      const existing = counts.get(codepoint);
      counts.set(codepoint, {
        codepoint: "U+" + codepoint.toString(16).toUpperCase().padStart(4, "0"),
        label,
        count: (existing && existing.count ? existing.count : 0) + 1,
        kind: "strip",
      });
    }
    const hits = Array.from(counts.values());
    return {
      kind: "text",
      length: value.length,
      hits,
      suspicious_total: hits.reduce((sum, hit) => sum + hit.count, 0),
    };
  }

  function localCleanText(value) {
    let cleaned = Array.from(value)
      .filter((character) => !LOCAL_REMOVABLE_MARKS.has(character.codePointAt(0)))
      .join("");
    if (textNfkc.checked) cleaned = cleaned.normalize("NFKC");
    return cleaned;
  }

  function detectionLines(detection) {
    if (!detection) return [];
    if (detection.ok === false) {
      return [t("deep_scan") + ": unavailable · " + (detection.error || t("detector_unavailable"))];
    }

    const lines = [t("deep_scan") + ":"];
    const detections = Array.isArray(detection.detections) ? detection.detections : [];
    if (!detections.length) {
      lines.push(t("scan_no_extra"));
      return lines;
    }

    for (const item of detections) {
      const name = item && item.detector ? item.detector : "detector";
      if (item && item.available === false) {
        lines.push(name + ": " + t("detector_not_configured"));
        continue;
      }
      if (item && typeof item.is_watermarked === "boolean") {
        lines.push(name + ": " + (item.is_watermarked ? t("candidate_found") : t("candidate_clean")));
      } else if (item && item.status) {
        lines.push(name + ": " + item.status);
      } else {
        lines.push(name + ": " + t("detector_returned"));
      }
      if (item && typeof item.score === "number") {
        const threshold = typeof item.threshold === "number" ? " / " + t("threshold_label") + " " + item.threshold : "";
        lines.push("  " + t("score_label") + ": " + item.score + threshold);
      }
      if (item && item.error) lines.push("  " + t("error_label") + ": " + item.error);
    }
    return lines;
  }

  function analysisText(report, detection) {
    const lines = [];
    if (report && report.kind) lines.push(t("report_type") + ": " + report.kind);
    if (report && report.format) lines.push(t("report_format") + ": " + report.format);
    if (report && report.suspicious_total) {
      lines.push(t("report_suspicious") + ": " + report.suspicious_total);
    }

    const hits = report && Array.isArray(report.hits) ? report.hits : [];
    for (const hit of hits) {
      const count = typeof hit.count === "number" ? " × " + hit.count : "";
      const confidence = hit.confidence ? " · " + hit.confidence : "";
      lines.push((hit.codepoint || "MARK") + "  " + (hit.label || "可疑标记") + count + confidence);
    }

    const findings = report && Array.isArray(report.findings) ? report.findings : [];
    for (const finding of findings) {
      lines.push(t("report_problem") + ": " + finding);
    }

    if (report && report.has_c2pa) lines.push(t("report_problem") + ": " + t("report_c2pa"));
    if (report && report.has_ai_metadata) lines.push(t("report_problem") + ": " + t("report_ai_metadata"));

    if (report && report.stats) {
      const removed = typeof report.stats.removed_count === "number"
        ? report.stats.removed_count
        : null;
      const replaced = typeof report.stats.replaced_count === "number"
        ? report.stats.replaced_count
        : null;
      if (removed !== null || replaced !== null) {
        const stats = [];
        if (removed !== null) stats.push("removed " + removed);
        if (replaced !== null) stats.push("replaced " + replaced);
        lines.push(t("report_action") + ": " + stats.join(", "));
      }
    }

    lines.push(...detectionLines(detection));

    if (!lines.length) {
      lines.push(t("report_clean"));
    }
    return lines.join("\n");
  }

  function reportHasFindings(report, detection) {
    const detectionHasFinding = Boolean(
      detection
      && Array.isArray(detection.detections)
      && detection.detections.some((item) => item && item.is_watermarked === true),
    );
    return Boolean(
      report && (
        (Array.isArray(report.hits) && report.hits.length)
        || (Array.isArray(report.findings) && report.findings.length)
        || report.suspicious_total
        || report.has_c2pa
        || report.has_ai_metadata
      ) || detectionHasFinding,
    );
  }

  function updateCharacterCount() {
    const count = textInput.value.length;
    characterCount.textContent = t("char_count", {
      count: count.toLocaleString(),
      max: MAX_TEXT_CHARACTERS.toLocaleString(),
    });
    characterCount.classList.toggle("is-over", count > MAX_TEXT_CHARACTERS);
    if (count > MAX_TEXT_CHARACTERS) {
      submitHint.textContent = t("text_limit", { max: MAX_TEXT_CHARACTERS.toLocaleString() });
    } else if (!state.attachment) {
      submitHint.textContent = t("hint_ready", { max: MAX_TEXT_CHARACTERS.toLocaleString() });
    }
  }

  function updateSubmitState() {
    const hasText = Boolean(textInput.value.trim());
    const hasAttachment = Boolean(state.attachment);
    const disabled = state.busy || (!hasText && !hasAttachment) || textInput.value.length > MAX_TEXT_CHARACTERS;
    submitButton.disabled = disabled;
    scanButton.disabled = disabled;
  }

  function clearPreviewUrl() {
    if (state.previewUrl) {
      URL.revokeObjectURL(state.previewUrl);
      state.previewUrl = null;
    }
  }

  function clearOutput() {
    clearPreviewUrl();
    outputPlaceholder.hidden = false;
    outputLoading.hidden = true;
    outputContent.hidden = true;
    analysisOutput.textContent = "";
    correctedOutput.textContent = "";
    fileResult.replaceChildren();
    fileResult.hidden = true;
    copyButton.hidden = false;
    state.outputModel = null;
    setOutputState("waiting");
  }

  function showLoading(scanOnly) {
    outputPlaceholder.hidden = true;
    outputLoading.hidden = false;
    outputContent.hidden = true;
    outputLoading.querySelector("span:last-child").textContent = t(scanOnly ? "loading_scan" : "loading_clean");
    setOutputState("busy");
  }

  function showAnalysis(report, local, detection, scanOnly) {
    const hasFindings = reportHasFindings(report, detection);
    state.outputModel = {
      report,
      detection,
      correctedKey: scanOnly ? "corrected_scan" : null,
      analysisTagKey: hasFindings ? "analysis_found" : "analysis_clean",
    };
    analysisOutput.textContent = analysisText(report, detection);
    analysisTag.textContent = t(state.outputModel.analysisTagKey);
    analysisTag.dataset.state = hasFindings ? "found" : "clean";
    outputContent.hidden = false;
    outputPlaceholder.hidden = true;
    outputLoading.hidden = true;
    setOutputState("ready", scanOnly
      ? (local ? "state_local_scan" : "state_scan_done")
      : (local ? "state_local_done" : "state_clean_done"));
  }

  function appendFileDownload(file, base64, filename) {
    const card = document.createElement("div");
    card.className = "file-result-card";

    const icon = document.createElement("span");
    icon.className = "file-result-icon";
    icon.textContent = extension(filename).toUpperCase().slice(0, 6);

    const meta = document.createElement("div");
    meta.className = "file-result-meta";
    const title = document.createElement("strong");
    title.textContent = filename;
    const detail = document.createElement("small");
    detail.textContent = t("cleaned_file_copy");
    meta.append(title, detail);

    const download = document.createElement("button");
    download.type = "button";
    download.className = "download-button";
    download.textContent = t("download");
    download.addEventListener("click", () => downloadBase64(
      base64,
      filename,
      file && file.type ? file.type : "application/octet-stream",
    ));

    card.append(icon, meta, download);
    fileResult.append(card);

    if (file && isImageFile(file)) {
      state.previewUrl = URL.createObjectURL(new Blob([base64ToBytes(base64)], {
        type: file.type || "image/*",
      }));
      const image = document.createElement("img");
      image.className = "file-preview-image";
      image.alt = "修正后的图片预览";
      image.src = state.previewUrl;
      fileResult.append(image);
    } else if (file && isVideoFile(file)) {
      state.previewUrl = URL.createObjectURL(new Blob([base64ToBytes(base64)], {
        type: file.type || "video/*",
      }));
      const video = document.createElement("video");
      video.className = "file-preview-video";
      video.controls = true;
      video.preload = "metadata";
      video.src = state.previewUrl;
      fileResult.append(video);
    }

    fileResult.hidden = false;
  }

  function renderTextResult(report, cleaned, local, file, base64, filename) {
    showAnalysis(report, local);
    state.outputModel.correctedKey = null;
    correctedOutput.textContent = cleaned;
    copyButton.hidden = false;
    copyButton.onclick = async () => {
      try {
        await navigator.clipboard.writeText(cleaned);
        copyButton.textContent = t("copied");
        setTimeout(() => { copyButton.textContent = t("copy_button"); }, 1400);
      } catch {
        copyButton.textContent = t("copy_failed");
        setTimeout(() => { copyButton.textContent = t("copy_button"); }, 1400);
      }
    };

    if (file && base64 && filename) {
      appendFileDownload(file, base64, filename);
    }
  }

  function renderScanResult(report, detection, local) {
    showAnalysis(report, local, detection, true);
    correctedOutput.textContent = t("corrected_scan");
    copyButton.hidden = true;
    fileResult.replaceChildren();
    fileResult.hidden = true;
  }

  function renderBinaryResult(report, result, file, local) {
    showAnalysis(report, local);
    state.outputModel.correctedKey = "binary_corrected";
    correctedOutput.textContent = t(state.outputModel.correctedKey);
    copyButton.hidden = true;
    appendFileDownload(file, result.cleaned, cleanedName(file.name));
  }

  function reportWithKind(payload) {
    const report = payload && payload.report && typeof payload.report === "object"
      ? { ...payload.report }
      : {};
    if (payload && payload.kind && !report.kind) report.kind = payload.kind;
    return report;
  }

  function cleanedName(filename) {
    const dot = filename.lastIndexOf(".");
    if (dot <= 0) return filename + ".cleaned";
    return filename.slice(0, dot) + ".cleaned" + filename.slice(dot);
  }

  function downloadBase64(base64, filename, mimeType) {
    const bytes = base64ToBytes(base64);
    const blob = new Blob([bytes], { type: mimeType || "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function textPayload(value) {
    if (!value.trim()) throw new Error(t("submit_empty"));
    if (value.length > MAX_TEXT_CHARACTERS) {
      throw new Error(t("text_limit_error", { max: MAX_TEXT_CHARACTERS.toLocaleString() }));
    }
    const payload = {
      file: bytesToBase64(new TextEncoder().encode(value)),
      name: "input.txt",
    };
    const options = cleanOptions();
    if (Object.keys(options).length) payload.options = options;
    return payload;
  }

  async function processText(value, localOnly) {
    if (localOnly || state.backendAvailable === false) {
      const report = localTextReport(value);
      renderTextResult(report, localCleanText(value), true);
      submitHint.textContent = t("hint_local_clean");
      return;
    }

    const payload = textPayload(value);
    const inspected = await request("/inspect", payload);
    const result = await request("/clean", payload);
    const removed = result.report && result.report.stats ? result.report.stats.removed_count : null;
    renderTextResult(reportWithKind(inspected), base64ToText(result.cleaned), false);
    submitHint.textContent = typeof removed === "number"
      ? t("hint_clean_removed", { count: removed })
      : t("hint_clean_done");
  }

  async function inspectWithDetection(payload) {
    const inspected = await request("/inspect", payload);
    let detection;
    try {
      detection = await request("/detect", {
        file: payload.file,
        name: payload.name,
      });
    } catch (error) {
      detection = {
        ok: false,
        error: error.message || "检测器未连接",
      };
    }
    return { inspected, detection };
  }

  async function processTextScan(value, localOnly) {
    if (localOnly || state.backendAvailable === false) {
      renderScanResult(
        localTextReport(value),
        { ok: false, error: t("local_unicode_scan") },
        true,
      );
      submitHint.textContent = t("hint_local_scan");
      return;
    }

    const payload = textPayload(value);
    const { inspected, detection } = await inspectWithDetection(payload);
    renderScanResult(reportWithKind(inspected), detection, false);
    submitHint.textContent = t("hint_scan_done");
  }

  async function processFile(file) {
    if (state.backendAvailable === false && isTextFile(file)) {
      const value = await file.text();
      const report = localTextReport(value);
      const cleaned = localCleanText(value);
      renderTextResult(report, cleaned, true, file, bytesToBase64(new TextEncoder().encode(cleaned)), cleanedName(file.name));
      submitHint.textContent = t("hint_text_local");
      return;
    }

    if (state.backendAvailable === false) {
      throw new Error(t("backend_file_error"));
    }

    const input = await encodedFile(file);
    const inspected = await request("/inspect", input);
    input.options = cleanOptions();
    const result = await request("/clean", input);
    const filename = cleanedName(file.name);

    if (result.kind === "text" || isTextFile(file)) {
      renderTextResult(
        reportWithKind(inspected),
        base64ToText(result.cleaned),
        false,
        file,
        result.cleaned,
        filename,
      );
    } else {
      renderBinaryResult(reportWithKind(inspected), result, file, false);
    }
    submitHint.textContent = t("hint_file_done");
  }

  async function processFileScan(file) {
    if (state.backendAvailable === false && isTextFile(file)) {
      const value = await file.text();
      renderScanResult(
        localTextReport(value),
        { ok: false, error: t("local_unicode_scan") },
        true,
      );
      submitHint.textContent = t("hint_text_local");
      return;
    }

    if (state.backendAvailable === false) {
      throw new Error(t("backend_scan_error"));
    }

    const input = await encodedFile(file);
    const { inspected, detection } = await inspectWithDetection(input);
    renderScanResult(reportWithKind(inspected), detection, false);
    submitHint.textContent = t("hint_file_scan_done");
  }

  async function submit(scanOnly) {
    if (state.busy) return;
    const value = textInput.value;
    const file = state.attachment;

    if (!value.trim() && !file) return;
    if (value.length > MAX_TEXT_CHARACTERS) {
      setError(t("text_limit_error", { max: MAX_TEXT_CHARACTERS.toLocaleString() }));
      return;
    }

    state.busy = true;
    setError("");
    updateSubmitState();
    clearOutput();
    showLoading(scanOnly);

    try {
      if (file) {
        if (scanOnly) {
          await processFileScan(file);
        } else {
          await processFile(file);
        }
      } else {
        if (scanOnly) {
          await processTextScan(value, false);
        } else {
          await processText(value, false);
        }
      }
    } catch (error) {
      if (isBackendUnavailable(error) && (!file || isTextFile(file))) {
        state.backendAvailable = false;
        setServiceStatus("error");
        try {
          if (file) {
            if (scanOnly) {
              await processFileScan(file);
            } else {
              await processFile(file);
            }
          } else {
            if (scanOnly) {
              await processTextScan(value, true);
            } else {
              await processText(value, true);
            }
          }
        } catch (fallbackError) {
          outputContent.hidden = true;
          outputLoading.hidden = true;
          outputPlaceholder.hidden = false;
          setOutputState("error");
          setError(fallbackError.message || t("processing_failed"));
        }
      } else {
        outputContent.hidden = true;
        outputLoading.hidden = true;
        outputPlaceholder.hidden = false;
        setOutputState("error");
        setError(error.message || t("processing_failed"));
        submitHint.textContent = t("processing_failed");
      }
    } finally {
      state.busy = false;
      updateSubmitState();
    }
  }

  function chooseAttachment(file) {
    if (!file) return;
    if (file.size > MAX_BROWSER_FILE_BYTES) {
      setError(t("file_size_error", { size: formatBytes(MAX_BROWSER_FILE_BYTES) }));
      return;
    }

    state.attachment = file;
    attachmentIcon.textContent = extension(file.name).toUpperCase().slice(0, 6);
    attachmentName.textContent = file.name + " · " + formatBytes(file.size);
    attachmentPreview.hidden = false;
    submitHint.textContent = t("attachment_added");
    updateSubmitState();
  }

  function clearAttachment() {
    state.attachment = null;
    attachmentInput.value = "";
    attachmentPreview.hidden = true;
    attachmentName.textContent = "—";
    updateSubmitState();
  }

  async function encodedFile(file) {
    return {
      file: bytesToBase64(new Uint8Array(await file.arrayBuffer())),
      name: file.name,
    };
  }

  function handleDrop(event) {
    event.preventDefault();
    cleanerCard.classList.remove("is-dragging");
    attachmentDropzone.classList.remove("is-dragging");

    const file = event.dataTransfer && event.dataTransfer.files
      ? event.dataTransfer.files[0]
      : null;
    if (file) {
      chooseAttachment(file);
      return;
    }

    const droppedText = event.dataTransfer ? event.dataTransfer.getData("text/plain") : "";
    if (droppedText) {
      const nextValue = textInput.value ? textInput.value + "\n" + droppedText : droppedText;
      textInput.value = nextValue.slice(0, MAX_TEXT_CHARACTERS);
      updateCharacterCount();
      updateSubmitState();
    }
  }

  async function checkService() {
    try {
      await request("/health");
      state.backendAvailable = true;
      setServiceStatus("ready");
      submitHint.textContent = t("hint_ready", { max: MAX_TEXT_CHARACTERS.toLocaleString() });
    } catch {
      state.backendAvailable = false;
      setServiceStatus("error");
      submitHint.textContent = t("hint_local_clean");
    }
  }

  attachButton.addEventListener("click", () => attachmentInput.click());
  attachmentDropzone.addEventListener("click", () => attachmentInput.click());
  attachmentInput.addEventListener("change", () => chooseAttachment(attachmentInput.files[0]));
  attachmentRemove.addEventListener("click", clearAttachment);
  scanButton.addEventListener("click", () => submit(true));
  submitButton.addEventListener("click", () => submit(false));
  languageSelect.addEventListener("change", () => {
    state.locale = languageSelect.value;
    try { window.localStorage.setItem("remove-watermark-locale", state.locale); } catch {}
    applyLanguage(state.locale);
  });
  themeSelect.addEventListener("change", () => {
    state.theme = themeSelect.value;
    try { window.localStorage.setItem("remove-watermark-theme", state.theme); } catch {}
    applyTheme(state.theme);
  });
  backToTop.addEventListener("click", () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
  window.addEventListener("scroll", () => {
    backToTop.hidden = window.scrollY < 560;
  }, { passive: true });

  textInput.addEventListener("input", () => {
    updateCharacterCount();
    updateSubmitState();
  });
  textInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      submit(false);
    }
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    cleanerCard.addEventListener(eventName, (event) => {
      event.preventDefault();
      cleanerCard.classList.add("is-dragging");
      attachmentDropzone.classList.add("is-dragging");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    cleanerCard.addEventListener(eventName, (event) => {
      event.preventDefault();
      if (eventName === "dragleave" && event.relatedTarget && cleanerCard.contains(event.relatedTarget)) return;
      cleanerCard.classList.remove("is-dragging");
      attachmentDropzone.classList.remove("is-dragging");
    });
  });
  cleanerCard.addEventListener("drop", handleDrop);

  applyTheme(state.theme);
  applyLanguage(state.locale);
  updateCharacterCount();
  updateSubmitState();
  backToTop.hidden = window.scrollY < 560;
  checkService();
})();
