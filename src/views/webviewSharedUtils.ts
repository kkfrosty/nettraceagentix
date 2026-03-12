/**
 * Shared utilities for webview panels (saved capture + live capture).
 * Provides TS-level helpers and embeddable JS/CSS snippets for webview HTML.
 */

// ─── TS-level utilities (used by extension host code) ────────────────

export function getNonce(): string {
    let text = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
        text += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return text;
}

export function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

export function formatBytes(bytes: number): string {
    if (bytes < 1024) { return `${bytes} B`; }
    if (bytes < 1024 * 1024) { return `${(bytes / 1024).toFixed(1)} KB`; }
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function getProtocolClass(protocol: string): string {
    const p = (protocol || '').toLowerCase();
    if (p === 'tcp') { return 'proto-tcp'; }
    if (p.includes('http')) { return 'proto-http'; }
    if (p.includes('tls') || p.includes('ssl')) { return 'proto-tls'; }
    if (p === 'dns') { return 'proto-dns'; }
    if (p === 'arp') { return 'proto-arp'; }
    if (p.includes('icmp')) { return 'proto-icmp'; }
    return '';
}

// ─── Embeddable webview JS ───────────────────────────────────────────

/**
 * Returns shared JS utility function definitions to embed in a webview <script> block.
 * Provides: escapeHtml(), formatBytes(), renderProtoTree(), renderProtoNode().
 */
export function getSharedWebviewJs(): string {
    return `
// ═══ Shared webview utilities ══════════════════════════════════
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatBytes(bytes) {
    var num = Number(bytes) || 0;
    if (num < 1024) { return num + ' B'; }
    if (num < 1024 * 1024) { return (num / 1024).toFixed(1) + ' KB'; }
    return (num / (1024 * 1024)).toFixed(1) + ' MB';
}

function renderProtoTree(nodes) {
    if (!nodes || nodes.length === 0) return '<div style="padding:8px;color:var(--vscode-descriptionForeground);">No detail available.</div>';
    var html = '<div class="proto-tree">';
    for (var i = 0; i < nodes.length; i++) {
        var isLast = (i === nodes.length - 1);
        html += renderProtoNode(nodes[i], 0, isLast);
    }
    html += '</div>';
    return html;
}

function renderProtoNode(node, depth, startExpanded) {
    var hasChildren = node.children && node.children.length > 0;
    var indent = depth * 16;
    var id = 'pn_' + Math.random().toString(36).substr(2, 9);
    var expanded = startExpanded === true;
    var html = '<div class="proto-node" style="padding-left:' + indent + 'px;">';
    if (hasChildren) {
        var arrow = expanded ? '\\u25bc' : '\\u25b6';
        var displayStyle = expanded ? 'block' : 'none';
        html += '<span class="proto-toggle" data-toggle="' + id + '" id="toggle_' + id + '">' + arrow + '</span> ';
        html += '<span class="proto-label ' + (depth === 0 ? 'proto-header' : 'proto-field') + '">' + escapeHtml(node.showname) + '</span>';
        html += '<div class="proto-children" id="' + id + '" style="display:' + displayStyle + ';">';
        for (var ci = 0; ci < node.children.length; ci++) {
            html += renderProtoNode(node.children[ci], depth + 1, false);
        }
        html += '</div>';
    } else {
        html += '<span style="display:inline-block;width:16px;"></span> ';
        html += '<span class="proto-field">' + escapeHtml(node.showname) + '</span>';
    }
    html += '</div>';
    return html;
}
// ═══ Context menu ══════════════════════════════════════════════
function closeCtxMenu(target) {
    var menu = document.getElementById('ctxMenu');
    if (menu && (!target || !menu.contains(target))) {
        menu.remove();
    }
}

function buildPacketMenuItems(el) {
    var src = el.getAttribute ? (el.getAttribute('data-src') || '') : (el.dataset && el.dataset.src || '');
    var dst = el.getAttribute ? (el.getAttribute('data-dst') || '') : (el.dataset && el.dataset.dst || '');
    var proto = el.getAttribute ? (el.getAttribute('data-proto') || '') : (el.dataset && el.dataset.proto || '');
    var stream = el.getAttribute ? (el.getAttribute('data-stream') || '') : (el.dataset && el.dataset.stream || '');
    var packetNum = el.getAttribute ? (el.getAttribute('data-packet') || el.getAttribute('data-f') || '') : (el.dataset && (el.dataset.packet || el.dataset.f) || '');

    var items = [];
    if (stream !== '') {
        items.push({ label: 'Filter: TCP Conversation (stream ' + stream + ')', filter: 'tcp.stream == ' + stream });
    }
    if (src) {
        items.push({ label: 'Filter: Source \\u2192 ' + src, filter: 'ip.addr == ' + src });
    }
    if (dst) {
        items.push({ label: 'Filter: Destination \\u2192 ' + dst, filter: 'ip.addr == ' + dst });
    }
    if (src && dst) {
        items.push({ label: 'Filter: Conversation ' + src + ' \\u2194 ' + dst, filter: 'ip.addr == ' + src + ' && ip.addr == ' + dst });
    }
    if (proto) {
        items.push({ label: 'Filter: Protocol ' + proto, filter: proto.toLowerCase() });
    }
    items.push(null);
    items.push({ label: 'Analyze Packet #' + packetNum + ' with AI', action: 'analyzePacket', packet: packetNum });
    if (stream !== '') {
        items.push({ label: 'Analyze TCP Stream ' + stream + ' with AI', action: 'analyzeStream', stream: stream });
    }
    items.push(null);
    items.push({ type: 'input', label: 'Go to Packet #', placeholder: 'Packet number', action: 'goToPacket' });
    return items;
}

function showCtxMenu(x, y, items, onFilter, onAction) {
    closeCtxMenu();
    var menu = document.createElement('div');
    menu.id = 'ctxMenu';
    menu.className = 'ctx-menu';
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';

    for (var i = 0; i < items.length; i++) {
        if (items[i] === null) {
            var sep = document.createElement('div');
            sep.className = 'ctx-menu-sep';
            menu.appendChild(sep);
        } else if (items[i].type === 'input') {
            var row = document.createElement('div');
            row.className = 'ctx-menu-input-row';
            var lbl = document.createElement('span');
            lbl.textContent = items[i].label;
            lbl.className = 'ctx-menu-input-label';
            var inp = document.createElement('input');
            inp.type = 'text';
            inp.className = 'ctx-menu-input';
            inp.placeholder = items[i].placeholder || '';
            inp.setAttribute('inputmode', 'numeric');
            inp.setAttribute('pattern', '[0-9]*');
            (function(item, input) {
                input.addEventListener('keydown', function(ev) {
                    if (ev.key === 'Enter') {
                        var val = input.value.trim();
                        if (val) {
                            menu.remove();
                            onAction(item.action, { packet: val });
                        }
                    }
                    ev.stopPropagation();
                });
                input.addEventListener('click', function(ev) { ev.stopPropagation(); });
            })(items[i], inp);
            row.appendChild(lbl);
            row.appendChild(inp);
            menu.appendChild(row);
        } else {
            var mi = document.createElement('div');
            mi.className = 'ctx-menu-item';
            mi.textContent = items[i].label;
            (function(item) {
                mi.addEventListener('click', function() {
                    menu.remove();
                    if (item.filter) {
                        onFilter(item.filter);
                    } else if (item.action) {
                        onAction(item.action, item);
                    }
                });
            })(items[i]);
            menu.appendChild(mi);
        }
    }

    document.body.appendChild(menu);
    var rect = menu.getBoundingClientRect();
    if (rect.right > window.innerWidth) { menu.style.left = (window.innerWidth - rect.width - 4) + 'px'; }
    if (rect.bottom > window.innerHeight) { menu.style.top = (window.innerHeight - rect.height - 4) + 'px'; }
}

// ═══ Bottom pane resizer ══════════════════════════════════════
function initBottomResizer(layoutEl, splitterEl, bottomEl, isCollapsed, minH, defaultH) {
    function setHeight(heightPx) {
        if (!layoutEl) { return; }
        var layoutHeight = layoutEl.getBoundingClientRect().height || 0;
        var maxHeight = Math.max(minH, Math.floor(layoutHeight * 0.75));
        var nextHeight = Math.max(minH, Math.min(heightPx, maxHeight));
        layoutEl.style.setProperty('--ws-bottom-height', nextHeight + 'px');
        bottomEl.dataset.lastHeight = String(nextHeight);
    }
    function restoreHeight() {
        var lastHeight = parseInt(bottomEl.dataset.lastHeight || '', 10);
        setHeight(Number.isNaN(lastHeight) ? defaultH : lastHeight);
    }
    if (splitterEl && layoutEl) {
        var dragging = false;
        function stopDragging() {
            if (!dragging) { return; }
            dragging = false;
            splitterEl.classList.remove('dragging');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }
        splitterEl.addEventListener('mousedown', function(e) {
            if (isCollapsed()) { return; }
            dragging = true;
            splitterEl.classList.add('dragging');
            document.body.style.cursor = 'row-resize';
            document.body.style.userSelect = 'none';
            e.preventDefault();
        });
        window.addEventListener('mousemove', function(e) {
            if (!dragging || !layoutEl) { return; }
            var layoutRect = layoutEl.getBoundingClientRect();
            setHeight(layoutRect.bottom - e.clientY);
        });
        window.addEventListener('mouseup', stopDragging);
        window.addEventListener('mouseleave', stopDragging);
    }
    return { setHeight: setHeight, restoreHeight: restoreHeight };
}

// ═══ End shared webview utilities ══════════════════════════════`;
}

// ─── Embeddable shared CSS ───────────────────────────────────────────

/**
 * Returns shared CSS rules to embed in a webview <style> block.
 * Uses raw VS Code theme variables to avoid dependency on viewer-specific custom properties.
 * Covers: proto tree, expert entries, badges, side panel items, context menu, loading cells.
 */
export function getSharedCss(): string {
    return `
/* ═══ Shared CSS (from webviewSharedUtils) ════════════════════ */

/* ── Protocol Detail Tree ──────────────────────── */
.proto-tree { font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; padding: 4px 0; }
.proto-node { padding: 1px 0; line-height: 1.5; white-space: nowrap; }
.proto-toggle { cursor: pointer; display: inline-block; width: 16px; text-align: center; font-size: 10px; color: var(--vscode-descriptionForeground, #888); user-select: none; vertical-align: middle; }
.proto-toggle:hover { color: var(--vscode-foreground); }
.proto-header { font-weight: 600; color: var(--vscode-foreground); }
.proto-field { color: var(--vscode-foreground); }
.proto-label { cursor: pointer; }
.proto-label:hover { background: var(--vscode-list-hoverBackground, rgba(255,255,255,0.07)); border-radius: 2px; }

/* ── Expert info entries ───────────────────────── */
.expert-entry { padding: 4px 8px; font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; border-left: 3px solid transparent; margin-bottom: 2px; }
.expert-error { border-left-color: #f44; background: rgba(255,0,0,0.05); }
.expert-warning { border-left-color: #fa0; background: rgba(255,165,0,0.05); }
.expert-note { border-left-color: #0af; background: rgba(0,170,255,0.05); }

/* ── Badges ────────────────────────────────────── */
.badge { display: inline-block; padding: 1px 6px; border-radius: 10px; font-size: 11px; }
.badge-warning { background: rgba(255,165,0,0.2); color: #fa0; }
.badge-ok { color: #4c4; }

/* ── Side panel items ──────────────────────────── */
.side-panel { padding: 12px; overflow: auto; }
.proto-item { display: flex; justify-content: space-between; padding: 3px 8px; border-bottom: 1px solid var(--vscode-panel-border, #333); }
.proto-name { font-weight: 500; }
.proto-count { color: var(--vscode-descriptionForeground, #888); }

/* ── Context menu ──────────────────────────────── */
.ctx-menu { position: fixed; z-index: 1000; background: var(--vscode-sideBar-background, #252526); border: 1px solid var(--vscode-panel-border, #333); border-radius: 4px; padding: 4px 0; box-shadow: 0 4px 12px rgba(0,0,0,0.3); min-width: 220px; font-size: 12px; }
.ctx-menu-item { padding: 5px 16px; cursor: pointer; white-space: nowrap; }
.ctx-menu-item:hover { background: var(--vscode-list-hoverBackground, rgba(255,255,255,0.05)); }
.ctx-menu-sep { height: 1px; background: var(--vscode-panel-border, #333); margin: 4px 0; }
.ctx-menu-input-row { display: flex; align-items: center; gap: 6px; padding: 4px 12px; }
.ctx-menu-input-label { font-size: 12px; white-space: nowrap; color: var(--vscode-foreground); }
.ctx-menu-input { flex: 1; min-width: 70px; padding: 2px 6px; font-size: 12px; border: 1px solid var(--vscode-panel-border, #555); border-radius: 3px; background: var(--vscode-input-background, #3c3c3c); color: var(--vscode-input-foreground, #ccc); outline: none; }
.ctx-menu-input:focus { border-color: var(--vscode-focusBorder, #007fd4); }

/* ── Loading / empty indicators ────────────────── */
.loading-cell { padding: 16px 8px; color: var(--vscode-descriptionForeground, #888); text-align: center; font-style: italic; }

/* ═══ End shared CSS ═════════════════════════════════════════ */`;
}
