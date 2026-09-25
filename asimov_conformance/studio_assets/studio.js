(() => {
  "use strict";

  const params = new URLSearchParams(location.search);
  const token = params.get("token") || "";
  let state = null;
  let currentReview = null;
  let adapterCatalog = null;

  const $ = (id) => document.getElementById(id);
  const val = (id) => $(id).value;
  const set = (id, value) => { $(id).value = value == null ? "" : value; };
  const lines = (text) => String(text || "").split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  const escapeHtml = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[c]));
  const pretty = (s) => String(s || "").replaceAll("_", " ").toLowerCase().replace(/\b\w/g, c => c.toUpperCase());

  function workspace() { return val("workspace-path").trim(); }

  function selectedChoices(id) {
    return Array.from($(id).querySelectorAll('input[type="checkbox"]:checked')).map(x => x.value);
  }

  function adapterAssistantPayload() {
    const runtime = val("aa-runtime");
    if (!runtime) throw new Error("Choose an agent runtime first.");
    return {
      runtime: runtime,
      hosting: val("aa-hosting") || null,
      authority: val("aa-authority") || null,
      resources: selectedChoices("aa-resources"),
      evidence: selectedChoices("aa-evidence"),
      integrations: selectedChoices("aa-integrations")
    };
  }

  function optionHtml(row, detailKey) {
    const detail = row[detailKey] || row.summary || row.role || "";
    return '<label class="choice"><input type="checkbox" value="' + escapeHtml(row.id) + '">' +
      '<span><strong>' + escapeHtml(row.name) + '</strong><small>' + escapeHtml(detail) + '</small></span></label>';
  }

  async function loadAdapterCatalog() {
    adapterCatalog = await apiGet("/api/adapter-catalog");
    const runtimes = adapterCatalog.runtime_options || [];
    $("aa-runtime").innerHTML = '<option value="">Choose runtime…</option>' + runtimes.map(r =>
      '<option value="' + escapeHtml(r.id) + '">' + escapeHtml(r.name) + '</option>'
    ).join("");
    $("aa-hosting").innerHTML = '<option value="">Choose hosting…</option>' + (adapterCatalog.hosting_options || []).map(r =>
      '<option value="' + escapeHtml(r.id) + '">' + escapeHtml(r.name) + '</option>'
    ).join("");
    $("aa-authority").innerHTML = '<option value="">Choose authority…</option>' + (adapterCatalog.authority_options || []).map(r =>
      '<option value="' + escapeHtml(r.id) + '">' + escapeHtml(r.name) + '</option>'
    ).join("");
    $("aa-resources").innerHTML = (adapterCatalog.resource_options || []).map(r => optionHtml(r, "oracle")).join("");
    $("aa-evidence").innerHTML = (adapterCatalog.evidence_options || []).map(r => optionHtml(r, "role")).join("");
    $("aa-integrations").innerHTML = (adapterCatalog.integration_options || []).map(r => optionHtml(r, "warning")).join("");
    $("adapter-assistant-status").textContent = "Catalog checked " + (adapterCatalog.checked_at || "");
  }

  function renderAdapterRecommendation(rec) {
    const runtime = rec.runtime || {};
    const mappings = (rec.surfaces || []).map(surface => {
      const mapped = runtime.recommended && runtime.recommended[surface.id] ? runtime.recommended[surface.id] : "Wire a real deployment surface.";
      return '<div class="surface-map-row"><b>' + escapeHtml(surface.name) + '</b><span>' + escapeHtml(mapped) + '</span></div>';
    }).join("");
    const warnings = []
      .concat(runtime.not_enough || [])
      .concat(rec.gaps || []);
    $("aa-recommendation").classList.remove("empty-state");
    $("aa-recommendation").innerHTML =
      '<div class="assistant-summary"><div><div class="overline">Suggested architecture</div><h3>' +
      escapeHtml(runtime.name || "Adapter") + '</h3><p>' + escapeHtml(runtime.summary || "") +
      '</p><ul class="warning-list">' + warnings.map(x => '<li>' + escapeHtml(x) + '</li>').join("") +
      '</ul></div><div class="surface-map">' + mappings + '</div></div>';
  }

  async function previewAdapterRecommendation() {
    busy(true, "Mapping your stack…", "Studio is matching provider hooks to Asimov's six deployment surfaces.");
    try {
      const rec = await apiPost("/api/adapter-recommendation", adapterAssistantPayload());
      renderAdapterRecommendation(rec);
    } finally { busy(false); }
  }

  async function generateStarterAdapter() {
    const payload = adapterAssistantPayload();
    payload.output_dir = val("aa-output").trim();
    payload.class_name = val("aa-class").trim() || "AsimovAdapter";
    payload.adapter_id = val("aa-id").trim() || "generated-adapter";
    busy(true, "Generating starter adapter…", "Studio is creating a fail-closed scaffold and stack-specific wiring guide.");
    try {
      const result = await apiPost("/api/generate-adapter", payload);
      set("adapter", result.adapter_spec);
      persistSessionFields();
      renderAdapterRecommendation(result.recommendation);
      toast("Starter adapter created. Studio populated the Adapter field; wire real controls before running doctor.");
      document.querySelector("#workspace").scrollIntoView({behavior: "smooth"});
    } finally { busy(false); }
  }

  function toast(message, bad) {
    const el = $("toast");
    el.textContent = message;
    el.classList.toggle("bad", !!bad);
    el.classList.remove("hidden");
    clearTimeout(el._timer);
    el._timer = setTimeout(() => el.classList.add("hidden"), 5000);
  }

  function busy(on, title, text) {
    $("busy-title").textContent = title || "Working…";
    $("busy-text").textContent = text || "Studio is running the Asimov engine locally.";
    $("busy").classList.toggle("hidden", !on);
  }

  async function request(path, options) {
    options = options || {};
    const headers = Object.assign({}, options.headers || {}, {"X-Asimov-Studio-Token": token});
    if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
    const response = await fetch(path, Object.assign({}, options, {headers}));
    let data;
    try { data = await response.json(); }
    catch (_) { data = {error: "Studio returned an unreadable response."}; }
    if (!response.ok) throw new Error(data.error || ("Studio request failed (" + response.status + ")"));
    return data;
  }

  function apiGet(path, query) {
    const q = new URLSearchParams(query || {});
    return request(path + "?" + q.toString());
  }
  const apiPost = (path, body) => request(path, {method: "POST", body: JSON.stringify(body)});

  function adapterPayload() {
    let kwargs = {};
    const raw = val("adapter-kwargs").trim() || "{}";
    try { kwargs = JSON.parse(raw); }
    catch (_) { throw new Error("Adapter settings must be valid JSON."); }
    if (!kwargs || Array.isArray(kwargs) || typeof kwargs !== "object") throw new Error("Adapter settings must be a JSON object.");
    return {adapter: val("adapter").trim(), adapter_kwargs: kwargs, level: val("level")};
  }

  function persistSessionFields() {
    sessionStorage.setItem("asimov.studio.adapter", val("adapter"));
    sessionStorage.setItem("asimov.studio.adapter_kwargs", val("adapter-kwargs"));
    localStorage.setItem("asimov.studio.workspace", workspace());
  }

  function restoreSessionFields() {
    const initialWorkspace = params.get("workspace") || localStorage.getItem("asimov.studio.workspace");
    if (initialWorkspace) set("workspace-path", initialWorkspace);
    const adapter = sessionStorage.getItem("asimov.studio.adapter");
    const kwargs = sessionStorage.getItem("asimov.studio.adapter_kwargs");
    if (adapter) set("adapter", adapter);
    if (kwargs) set("adapter-kwargs", kwargs);
  }

  async function loadWorkspace(showMessage) {
    persistSessionFields();
    const root = workspace();
    if (!root) return;
    state = await apiGet("/api/state", {workspace: root});
    renderState();
    if (showMessage) toast(state.prepared ? "Workspace opened." : "No prepared assessment exists in that folder yet.");
  }

  function renderState() {
    const prepared = !!(state && state.prepared);
    const plan = (state && state.plan) || {};
    const status = (state && state.status) || {};
    const scope = (state && state.scope) || {};
    const reviews = (state && state.reviews) || [];

    $("state-pill").textContent = prepared ? ((plan.requested_profile || "") + " · " + pretty(plan.state || "prepared")) : "No workspace";
    $("workspace-status").textContent = prepared ? "Prepared" : "Not prepared";
    $("scope-status").textContent = prepared ? (scope.scope_description ? "Defined" : "Needs description") : "Workspace required";
    $("run-status").textContent = state && state.technical ? "Technical run complete" : prepared ? "Ready when acknowledged" : "Not run";
    $("finish-status").textContent = state && state.finalized ? pretty((state.result && state.result.reported_outcome) || "Finalized") : "Not finalized";

    if (prepared) {
      if (!val("adapter")) set("adapter", plan.adapter_spec || "");
      set("level", plan.requested_profile || "A5");
      set("mode", plan.assessment_mode || "self_assessment");
      set("assessor", plan.assessor || "");
      set("subject-org", plan.subject_organization || "");
      set("assessor-org", plan.assessor_organization || "");
      set("scope-description", scope.scope_description || "");
      set("threat-model", scope.threat_model || "");
      set("exclusions", (scope.exclusions || []).join("\n"));
      if (!val("ack-reviewer")) set("ack-reviewer", plan.assessor || "");
    }

    renderReviews(reviews);
    renderTechnical();
    renderFinish();
    renderReviewStatus(reviews, status);
  }

  function renderReviewStatus(reviews, status) {
    if (!state || !state.prepared) {
      $("reviews-status").textContent = "No workspace";
      return;
    }
    const family = reviews.filter(r => r.item_type === "requirement");
    const complete = family.filter(r => ["PASS","FAIL"].includes(r.decision) && r.signed).length;
    $("reviews-status").textContent = family.length ? (complete + " / " + family.length + " signed decisions") : "No family reviews";
    if (status.pre_run_ready === false) $("run-status").textContent = "Acknowledgement required";
  }

  function badgeClass(decision) {
    if (decision === "FAIL") return "fail";
    if (decision === "PASS") return "";
    return "pending";
  }

  function renderReviews(reviews) {
    const target = $("review-list");
    if (!reviews.length) {
      target.innerHTML = '<div class="empty-state">No generated review records yet.</div>';
      return;
    }
    const ordered = reviews.slice().sort((a,b) => {
      if (a.item_type !== b.item_type) return a.item_type === "precondition" ? -1 : 1;
      return String(a.item_id).localeCompare(String(b.item_id));
    });
    target.innerHTML = ordered.map(r => {
      const relation = r.item_type === "precondition" ? "Precondition" : pretty(r.review_requirement);
      const signed = r.item_type === "requirement" && r.signed ? '<span class="badge signed">Signed</span>' : "";
      return '<div class="review-card" data-type="' + escapeHtml(r.item_type) + '" data-id="' + escapeHtml(r.item_id) + '">' +
        '<div class="review-code">' + escapeHtml(r.item_id) + '</div>' +
        '<div><div class="review-name">' + escapeHtml(r.title || r.item_id) + '</div>' +
        '<div class="review-meta">' + escapeHtml(relation) + ' · ' + escapeHtml(r.reviewer || "Reviewer not assigned") + '</div></div>' +
        '<div class="review-badges"><span class="badge ' + badgeClass(r.decision) + '">' + escapeHtml(r.decision) + '</span>' + signed + '</div></div>';
    }).join("");
    target.querySelectorAll(".review-card").forEach(el => el.addEventListener("click", () => openReview(el.dataset.type, el.dataset.id)));
  }

  function renderTechnical() {
    const target = $("technical-summary");
    const counts = state && state.technical && state.technical.counts;
    if (!counts) { target.innerHTML = ""; return; }
    const keys = ["PASS","FAIL","ERROR","NOT_TESTED","INCONCLUSIVE"];
    target.innerHTML = keys.filter(k => counts[k]).map(k =>
      '<div class="metric"><b>' + counts[k] + '</b><span>' + pretty(k) + '</span></div>'
    ).join("");
  }

  function renderFinish() {
    const finalized = !!(state && state.finalized);
    $("finalize").disabled = !(state && state.technical);
    $("sign-report").disabled = !finalized;
    $("verify-package").disabled = !finalized;
    $("open-report").disabled = !(state && state.artifacts && state.artifacts["report.html"]);
    const sig = state && state.report_signature;
    if (sig && sig.signed) {
      $("finish-status").textContent = pretty((state.result && state.result.reported_outcome) || "Finalized") + " · report signed";
      if (!val("report-identity")) set("report-identity", sig.identity || "");
    }
  }

  async function prepare() {
    persistSessionFields();
    const a = adapterPayload();
    busy(true, "Preparing assessment…", "Studio is creating the scope, review records, and verification plan.");
    try {
      state = await apiPost("/api/prepare", Object.assign({}, a, {
        workspace: workspace(),
        assessor: val("assessor").trim(),
        subject_organization: val("subject-org").trim(),
        assessor_organization: val("assessor-org").trim(),
        mode: val("mode")
      }));
      renderState();
      toast("Assessment workspace prepared.");
    } finally { busy(false); }
  }

  async function saveScope() {
    busy(true, "Saving scope…");
    try {
      state = await apiPost("/api/scope", {
        workspace: workspace(),
        scope_description: val("scope-description"),
        threat_model: val("threat-model"),
        exclusions: lines(val("exclusions"))
      });
      renderState();
      toast("Scope saved.");
    } finally { busy(false); }
  }

  async function checkReadiness() {
    persistSessionFields();
    const a = adapterPayload();
    busy(true, "Checking readiness…", "Studio is comparing the adapter's real capabilities with the requested profile.");
    try {
      const result = await apiPost("/api/readiness", a);
      $("readiness-status").textContent = result.ready ? "Ready to test" : (result.blockers + " blockers");
      $("readiness-results").innerHTML = result.findings.map(f =>
        '<div class="result-row"><code>' + escapeHtml(f.requirement_id) + '</code>' +
        '<div class="result-state ' + (f.state === "READY_TO_TEST" ? "ok" : "bad") + '">' + escapeHtml(pretty(f.state)) + '</div>' +
        '<p>' + escapeHtml(f.remediation) + '</p></div>'
      ).join("");
      toast(result.ready ? "No capability blockers detected." : (result.blockers + " readiness blockers found."), !result.ready);
    } finally { busy(false); }
  }

  async function acknowledge() {
    busy(true, "Acknowledging obligations…");
    try {
      state = await apiPost("/api/acknowledge", {
        workspace: workspace(),
        reviewer: val("ack-reviewer").trim(),
        reviewer_role: val("ack-role").trim()
      });
      renderState();
      toast("Pre-run obligations acknowledged. This is not a PASS.");
    } finally { busy(false); }
  }

  async function runAssessment() {
    persistSessionFields();
    const a = adapterPayload();
    busy(true, "Running technical assessment…", "This can take time. Studio is exercising the same probes as the CLI.");
    try {
      state = await apiPost("/api/run", Object.assign({}, a, {workspace: workspace()}));
      renderState();
      toast("Technical assessment complete.");
    } finally { busy(false); }
  }

  async function openReview(itemType, itemId) {
    try {
      currentReview = await apiGet("/api/review", {workspace: workspace(), item_type: itemType, item_id: itemId});
      populateReview(currentReview);
      $("review-dialog").showModal();
    } catch (e) { toast(e.message, true); }
  }

  function populateReview(r) {
    set("review-item-type", r.item_type);
    set("review-item-id", r.item_id);
    $("review-title").textContent = r.item_id + " · " + (r.title || "Review");
    const relation = r.item_type === "precondition" ? "Assessment precondition" : pretty(r.review_requirement);
    $("review-type-label").textContent = relation;
    $("review-banner").innerHTML = r.item_type === "precondition"
      ? "<strong>Precondition.</strong> This record is mandatory and package-bound, but Asimov 0.2 does not require a separate reviewer signature."
      : "<strong>" + escapeHtml(pretty(r.review_requirement)) + ".</strong> Complete the evidence judgment, then sign this exact family review with the reviewer's own identity.";

    set("reviewer-name", r.reviewer || "");
    set("reviewer-role", r.reviewer_role || "");
    set("reviewer-org", r.reviewer_organization || "");
    set("review-subject-org", r.subject_organization || (state && state.plan && state.plan.subject_organization) || "");
    $("role-separated").checked = r.role_separated_from_implementation === true;
    $("role-separated-wrap").classList.toggle("hidden", r.review_requirement !== "ROLE_SEPARATED");

    const third = r.review_requirement === "THIRD_PARTY";
    $("independence-section").classList.toggle("hidden", !third);
    $("separate-entity").checked = r.independence && r.independence.separate_legal_entity === true;
    $("subject-no-control").checked = r.independence && r.independence.subject_controls_assessment === false;
    $("non-contingent").checked = r.independence && r.independence.outcome_contingent_compensation === false;
    set("conflicts", ((r.independence && r.independence.conflicts_disclosed) || []).join("\n"));
    set("relationship", r.relationship_to_target || "");

    set("review-decision", r.decision || "PENDING");
    set("review-evidence", (r.evidence_refs || []).join("\n"));
    set("review-rationale", r.rationale || "");

    const checklist = Array.isArray(r.checklist) ? r.checklist : [];
    $("checklist").innerHTML = checklist.map((item, i) =>
      '<div class="check-item" data-check="' + i + '">' +
      '<div class="check-row"><div class="check-title"><strong>' + escapeHtml(item.id) + '</strong><br>' + escapeHtml(item.instruction) + '</div>' +
      '<select class="check-status">' +
      ["PENDING","PASS","FAIL","INCONCLUSIVE"].map(x => '<option' + (item.status === x ? " selected" : "") + '>' + x + '</option>').join("") +
      '</select></div>' +
      '<input class="check-evidence" value="' + escapeHtml((item.evidence_refs || []).join(", ")) + '" placeholder="Evidence references, comma separated"></div>'
    ).join("");

    $("review-signing").classList.toggle("hidden", r.item_type !== "requirement");
    set("review-sign-identity", (r.signing_identity && r.signing_identity.expected_subject) || "");
    const provider = providerFromIssuer(r.signing_identity && r.signing_identity.expected_issuer);
    set("review-sign-provider", provider);
    set("review-sign-issuer", provider === "custom" ? ((r.signing_identity && r.signing_identity.expected_issuer) || "") : "");
    $("review-sign-issuer").classList.toggle("hidden", provider !== "custom");
  }

  function providerFromIssuer(issuer) {
    const map = {
      "https://accounts.google.com": "google",
      "https://github.com/login/oauth": "github",
      "https://login.microsoftonline.com": "microsoft",
      "https://token.actions.githubusercontent.com": "github-actions"
    };
    return issuer ? (map[issuer] || "custom") : "google";
  }

  function collectReview() {
    const relation = currentReview.review_requirement || "HUMAN";
    const checklist = Array.from($("checklist").querySelectorAll(".check-item")).map((el, i) => ({
      id: currentReview.checklist[i].id,
      instruction: currentReview.checklist[i].instruction,
      status: el.querySelector(".check-status").value,
      evidence_refs: el.querySelector(".check-evidence").value.split(",").map(x => x.trim()).filter(Boolean)
    }));
    const third = relation === "THIRD_PARTY";
    const defaultIndependence = {
      separate_legal_entity: null,
      subject_controls_assessment: null,
      outcome_contingent_compensation: null,
      conflicts_disclosed: [],
      attested: false
    };
    return {
      reviewer: val("reviewer-name").trim(),
      reviewer_role: val("reviewer-role").trim(),
      reviewer_organization: val("reviewer-org").trim(),
      subject_organization: val("review-subject-org").trim(),
      party_class: third ? "THIRD_PARTY" : (currentReview.party_class || "FIRST_PARTY"),
      role_separated_from_implementation: relation === "ROLE_SEPARATED" ? $("role-separated").checked : currentReview.role_separated_from_implementation === true,
      review_type: third ? "independent_assessment" : (currentReview.review_type || "self_assessment"),
      relationship_to_target: third ? val("relationship").trim() : (currentReview.relationship_to_target || ""),
      independence: third ? {
        separate_legal_entity: $("separate-entity").checked,
        subject_controls_assessment: $("subject-no-control").checked ? false : true,
        outcome_contingent_compensation: $("non-contingent").checked ? false : true,
        conflicts_disclosed: lines(val("conflicts")),
        attested: $("separate-entity").checked && $("subject-no-control").checked && $("non-contingent").checked
      } : (currentReview.independence || defaultIndependence),
      decision: val("review-decision"),
      rationale: val("review-rationale").trim(),
      evidence_refs: lines(val("review-evidence")),
      checklist: checklist
    };
  }

  async function saveCurrentReview(closeDialog) {
    if (!currentReview) return;
    currentReview = await apiPost("/api/review", {
      workspace: workspace(),
      item_type: currentReview.item_type,
      item_id: currentReview.item_id,
      record: collectReview()
    });
    await loadWorkspace();
    if (closeDialog) $("review-dialog").close();
    else populateReview(currentReview);
    toast("Review saved.");
  }

  async function signCurrentReview() {
    if (!currentReview || currentReview.item_type !== "requirement") return;
    busy(true, "Signing human review…", "Cosign may open an authentication flow. Authenticate as the reviewer identity shown here.");
    try {
      await saveCurrentReview(false);
      const provider = val("review-sign-provider");
      const result = await apiPost("/api/sign-review", {
        workspace: workspace(),
        item_type: currentReview.item_type,
        item_id: currentReview.item_id,
        identity: val("review-sign-identity").trim(),
        provider: provider,
        oidc_issuer: provider === "custom" ? val("review-sign-issuer").trim() : null
      });
      state = result.state;
      renderState();
      currentReview = await apiGet("/api/review", {workspace: workspace(), item_type: currentReview.item_type, item_id: currentReview.item_id});
      populateReview(currentReview);
      toast("Review signed and verified.");
    } finally { busy(false); }
  }

  async function finalizeAssessment() {
    busy(true, "Finalizing assessment…", "Studio is merging results fail-closed and building the report and verification package.");
    try {
      state = await apiPost("/api/finalize", {workspace: workspace()});
      renderState();
      toast("Finalized: " + pretty((state.result && state.result.reported_outcome) || "complete"));
    } finally { busy(false); }
  }

  async function signReport() {
    const provider = val("report-provider");
    busy(true, "Signing public report…", "Cosign may open an authentication flow. Use the exact account you want attached to the report.");
    try {
      state = await apiPost("/api/sign-report", {
        workspace: workspace(),
        identity: val("report-identity").trim(),
        provider: provider,
        oidc_issuer: provider === "custom" ? val("report-issuer").trim() : null
      });
      renderState();
      toast("Public report signed and verified.");
    } finally { busy(false); }
  }

  async function verifyPackage() {
    busy(true, "Verifying complete package…", "Studio is checking evidence binding, review attestations, and report provenance locally.");
    try {
      const result = await apiPost("/api/verify", {workspace: workspace()});
      const bad = result.overall === "FAILED";
      $("verification-result").innerHTML =
        '<div class="verify-summary ' + (bad ? "bad" : "") + '"><h3>' + escapeHtml(pretty(result.overall)) + '</h3>' +
        '<p>Evidence: ' + escapeHtml(result.checks && result.checks.evidence_integrity && result.checks.evidence_integrity.state || "—") +
        ' · Review attestations: ' + escapeHtml(result.checks && result.checks.review_attestations && result.checks.review_attestations.state || "—") +
        ' · Package signature: ' + escapeHtml(result.checks && result.checks.sigstore_identity_and_transparency && result.checks.sigstore_identity_and_transparency.state || "—") +
        '</p></div>';
      await loadWorkspace();
      toast(bad ? "Package verification failed. Inspect the receipt." : "Package verification complete.", bad);
    } finally { busy(false); }
  }

  function openReport() {
    const q = new URLSearchParams({workspace: workspace(), token: token});
    window.open("/report?" + q.toString(), "_blank", "noopener");
  }

  function bind() {
    $("aa-preview").addEventListener("click", () => action(previewAdapterRecommendation));
    $("aa-generate").addEventListener("click", () => action(generateStarterAdapter));
    $("aa-runtime").addEventListener("change", () => {
      if (val("aa-runtime")) action(previewAdapterRecommendation);
    });
    $("open-workspace").addEventListener("click", () => action(() => loadWorkspace(true)));
    $("refresh").addEventListener("click", () => action(() => loadWorkspace(false)));
    $("prepare").addEventListener("click", () => action(prepare));
    $("save-scope").addEventListener("click", () => action(saveScope));
    $("check-readiness").addEventListener("click", () => action(checkReadiness));
    $("acknowledge").addEventListener("click", () => action(acknowledge));
    $("run-assessment").addEventListener("click", () => action(runAssessment));
    $("save-review").addEventListener("click", () => action(() => saveCurrentReview(false)));
    $("sign-review").addEventListener("click", () => action(signCurrentReview));
    $("finalize").addEventListener("click", () => action(finalizeAssessment));
    $("sign-report").addEventListener("click", () => action(signReport));
    $("verify-package").addEventListener("click", () => action(verifyPackage));
    $("open-report").addEventListener("click", openReport);

    $("review-sign-provider").addEventListener("change", () => $("review-sign-issuer").classList.toggle("hidden", val("review-sign-provider") !== "custom"));
    $("report-provider").addEventListener("change", () => $("report-issuer-wrap").classList.toggle("hidden", val("report-provider") !== "custom"));

    ["adapter","adapter-kwargs","workspace-path"].forEach(id => $(id).addEventListener("change", persistSessionFields));
    document.querySelectorAll(".rail nav a").forEach(a => a.addEventListener("click", () => {
      document.querySelectorAll(".rail nav a").forEach(x => x.classList.remove("active"));
      a.classList.add("active");
    }));
  }

  async function action(fn) {
    try { await fn(); }
    catch (e) { busy(false); toast(e.message || String(e), true); }
  }

  async function start() {
    bind();
    restoreSessionFields();
    if (!token) {
      toast("Studio session token is missing. Relaunch with asimov studio.", true);
      return;
    }
    await action(loadAdapterCatalog);
    if (workspace()) await action(() => loadWorkspace(false));
  }

  start();
})();