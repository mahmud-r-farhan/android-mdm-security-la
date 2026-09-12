/*
 * Android MDM Security Lab - renderer logic
 * Talks to the main process exclusively through window.labAPI (preload bridge).
 * License: Apache License 2.0
 */

const $ = (id) => document.getElementById(id);

let currentReport = null;

function show(panelId) {
    for (const id of ['panel-empty', 'panel-results', 'panel-error']) {
        $(id).classList.toggle('hidden', id !== panelId);
    }
}

function setSpinner(visible) {
    $('spinner').classList.toggle('hidden', !visible);
    $('btn-scan').disabled = visible;
}

function errorValue(value) {
    if (typeof value !== 'string') return '—';
    if (value.startsWith('Error:')) return '—';
    return value || '—';
}

function renderResults(report) {
    currentReport = report;

    // ---- status badge ----------------------------------------------------
    const dpm = report.device_policy_management || {};
    const pkgs = report.detected_mdm_packages || [];
    const risk = (report.risk_assessment && report.risk_assessment.level) || 'LOW';

    const badge = $('status-badge');
    const headline = $('status-headline');
    const sub = $('status-sub');

    badge.className = 'big-badge';
    if (dpm.has_device_owner) {
        badge.classList.add('badge-danger');
        badge.textContent = 'MANAGED';
        headline.textContent = 'Device Owner active — full-device management enforced';
        sub.textContent = 'Uninstall protection, policy locks and settings restrictions can be applied by the owner app.';
    } else if (risk === 'MEDIUM' || dpm.has_profile_owner) {
        badge.classList.add('badge-warn');
        badge.textContent = dpm.has_profile_owner ? 'WORK PROFILE' : 'NOTICE';
        headline.textContent = dpm.has_profile_owner
            ? 'Managed work profile detected'
            : 'Known MDM / financing-lock software present';
        sub.textContent = 'Management software is installed but does not hold full device ownership.';
    } else {
        badge.classList.add('badge-safe');
        badge.textContent = 'SAFE';
        headline.textContent = 'No management detected';
        sub.textContent = 'No Device Owner, Profile Owner, or known MDM signatures were found.';
    }

    // ---- findings list ----------------------------------------------------
    const findingsList = $('findings-list');
    findingsList.innerHTML = '';
    const findings = (report.risk_assessment && report.risk_assessment.findings) || [];
    if (findings.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No management indicators found during this audit.';
        findingsList.appendChild(li);
    } else {
        for (const finding of findings) {
            const li = document.createElement('li');
            li.textContent = finding;
            findingsList.appendChild(li);
        }
    }

    // ---- device info ------------------------------------------------------
    const info = report.device_info || {};
    const kv = $('device-info');
    kv.innerHTML = '';
    const fields = [
        ['Manufacturer', info.manufacturer],
        ['Brand', info.brand],
        ['Model', info.model],
        ['Android', info.android_version],
        ['SDK level', info.sdk_level],
        ['Security patch', info.security_patch],
        ['Knox version', errorValue(info.knox_version)],
    ];
    for (const [label, value] of fields) {
        const dt = document.createElement('dt');
        dt.textContent = label;
        const dd = document.createElement('dd');
        dd.textContent = errorValue(value);
        kv.appendChild(dt);
        kv.appendChild(dd);
    }

    // ---- DPM badges ---------------------------------------------------------
    const badgeRow = $('dpm-badges');
    badgeRow.innerHTML = '';
    const doBadge = document.createElement('span');
    doBadge.className = 'mini-badge ' + (dpm.has_device_owner ? 'on-danger' : 'on-ok');
    doBadge.textContent = dpm.has_device_owner ? 'DEVICE OWNER: ACTIVE' : 'DEVICE OWNER: NONE';
    const poBadge = document.createElement('span');
    poBadge.className = 'mini-badge ' + (dpm.has_profile_owner ? 'on-warn' : 'on-ok');
    poBadge.textContent = dpm.has_profile_owner ? 'PROFILE OWNER: ACTIVE' : 'PROFILE OWNER: NONE';
    badgeRow.appendChild(doBadge);
    badgeRow.appendChild(poBadge);

    const owners = (dpm.active_admin_packages || []);
    $('dpm-owners').textContent = owners.length
        ? 'Admin packages: ' + owners.join(', ')
        : 'No active admin packages registered.';

    // ---- packages table ---------------------------------------------------
    const tbody = document.querySelector('#pkg-table tbody');
    tbody.innerHTML = '';
    $('pkg-table').classList.toggle('hidden', pkgs.length === 0);
    $('pkg-none').classList.toggle('hidden', pkgs.length !== 0);
    for (const pkg of pkgs) {
        const tr = document.createElement('tr');
        const tdName = document.createElement('td');
        tdName.textContent = pkg.package_name;
        const tdDesc = document.createElement('td');
        tdDesc.textContent = pkg.description;
        tr.appendChild(tdName);
        tr.appendChild(tdDesc);
        tbody.appendChild(tr);
    }

    $('raw-json').textContent = JSON.stringify(report, null, 2);
    show('panel-results');
}

async function refreshDevicePill() {
    const pill = $('device-pill');
    try {
        const result = await window.labAPI.listDevices();
        if (result.ok && result.devices.length > 0) {
            const authorized = result.devices.filter((d) => d.state === 'device');
            if (authorized.length > 0) {
                pill.textContent = `● ${authorized[0].serial}`;
                pill.className = 'pill pill-ok';
            } else {
                pill.textContent = `Device attached (${result.devices[0].state})`;
                pill.className = 'pill pill-warn';
            }
        } else {
            pill.textContent = 'No device connected';
            pill.className = 'pill pill-muted';
        }
    } catch (_err) {
        pill.textContent = 'adb unavailable';
        pill.className = 'pill pill-warn';
    }
}

async function runScan() {
    setSpinner(true);
    try {
        const result = await window.labAPI.runScan();
        if (result.ok && result.report) {
            renderResults(result.report);
        } else {
            $('error-detail').textContent = result.error || 'Unknown error.';
            show('panel-error');
        }
    } catch (err) {
        $('error-detail').textContent = String(err);
        show('panel-error');
    } finally {
        setSpinner(false);
        refreshDevicePill();
    }
}

async function exportReport() {
    if (!currentReport) return;
    const payload = JSON.stringify(currentReport, null, 2);
    const result = await window.labAPI.saveReport(payload);
    if (result.ok) {
        $('status-sub').textContent = `Report exported to ${result.filePath}`;
    }
}

$('btn-scan').addEventListener('click', runScan);
$('btn-retry').addEventListener('click', runScan);
$('btn-export').addEventListener('click', exportReport);

refreshDevicePill();
setInterval(refreshDevicePill, 15000);
