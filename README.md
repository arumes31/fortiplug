<div align="center">

<img src="icons/icon.svg" width="96" alt="FortiPlug logo">

# FortiPlug

**Power-user features for the FortiGate web GUI — as a Firefox extension.**

Copy the CLI config of filtered policies, copy & paste any policy, bulk-edit interfaces.

![Firefox](https://img.shields.io/badge/Firefox-115%2B-FF7139?logo=firefoxbrowser&logoColor=white)
![Manifest](https://img.shields.io/badge/Manifest-V2-informational)
![FortiOS](https://img.shields.io/badge/FortiOS-7.6-c8102e)
![No build step](https://img.shields.io/badge/build-none-success)
![Dependencies](https://img.shields.io/badge/dependencies-0-success)

[Features](#-features) · [Installation](#-installation) · [How to use](#-how-to-use) · [Configuration](#%EF%B8%8F-configuration) · [Troubleshooting](#-troubleshooting) · [Development](#-development)

</div>

---

## ✨ Features

| Feature | What it does | Where |
|---|---|---|
| 📋 **Copy filtered policies** | Copies the CLI config (`config firewall policy … end`) of every policy currently shown in the list — after search and filters — in GUI order. | FP button · `Alt+Shift+C` |
| 📑 **Copy / paste any policy** | Copy a policy and paste it above or below another one — also for policies with **multiple interfaces**, where the GUI's own paste is disabled. | Right-click a policy |
| 🔀 **Bulk edit interfaces** | Replace, add or remove **multiple** source / destination interfaces on many policies at once, with a live old → new preview. | FP button · right-click · `Alt+Shift+I` |
| ✏️ **Bulk rename policies** | Generate names from interfaces and services, add an optional software name, and review an editable preview. Automatically shortens names to 40 characters. | FP button · right-click |
| 🩺 **Diagnose** | Shows what FortiPlug detects on the page (columns, IDs, selection, last right-click). | FP button |

All changes go through the FortiGate REST API using **your existing GUI session** — no API token, no stored credentials.

---

## 📦 Installation

### Option A — Temporary (quickest, for testing)

1. Download or clone this repository:
   ```sh
   git clone https://github.com/arumes31/fortiplug.git
   ```
2. In Firefox, open **`about:debugging#/runtime/this-firefox`**.
3. Click **Load Temporary Add-on…** and select **`manifest.json`** in the cloned folder.
4. Open (or reload) your FortiGate GUI.

> [!NOTE]
> Temporary add-ons are removed when Firefox restarts. To update after a `git pull`, click **Reload** next to FortiPlug on the same page, then reload the FortiGate tab.

### Option B — Permanent (signed, recommended)

Firefox release only installs signed extensions. Signing as *unlisted* is free and the extension is **not** published on the store.

1. Create API credentials at **[addons.mozilla.org → Developer Hub → Manage API Keys](https://addons.mozilla.org/developers/addon/api/key/)**.
2. Sign the extension from the repository folder:
   ```sh
   # Read the credentials from the environment so the secret stays out of shell history and process listings
   export WEB_EXT_API_KEY='<JWT issuer>'
   read -rs WEB_EXT_API_SECRET && export WEB_EXT_API_SECRET   # paste the JWT secret, then Enter
   npx web-ext sign --channel=unlisted
   ```
3. The signed `.xpi` is written to `web-ext-artifacts/`.
4. In Firefox, open **`about:addons`** → ⚙️ gear icon → **Install Add-on From File…** → select the `.xpi`.

### Option C — Permanent, unsigned (Developer Edition / Nightly / ESR only)

1. Open **`about:config`**, set **`xpinstall.signatures.required`** to **`false`**.
2. Package the folder as an `.xpi` (a zip with `manifest.json` at the root):
   ```sh
   npx web-ext build          # → web-ext-artifacts/fortiplug-<version>.zip
   ```
   or zip the contents manually and rename the file to `fortiplug.xpi`.
3. **`about:addons`** → ⚙️ → **Install Add-on From File…** → select the file.

### Pin the toolbar icon

Firefox hides new extension icons in the **Extensions menu** (🧩 puzzle piece, right of the address bar):

1. Click 🧩 → find **FortiPlug** → click its ⚙️ gear → **Pin to Toolbar**.
2. Clicking the icon opens the popup with **On this page** (runnable actions) and **Features** (full list with usage).

### Permissions

On install Firefox asks to *access your data for all websites*. FortiPlug needs this because FortiGates live on arbitrary hosts/IPs and ports. The script activates **only** on pages it recognises as a FortiGate GUI and does nothing elsewhere. It requests no remote resources and sends nothing anywhere except your own FortiGate.

---

## 🚀 How to use

### Prepare the FortiGate policy list (once)

FortiPlug identifies policies by their ID, so the **ID column must be visible**:

1. Go to **Policy & Objects → Firewall Policy**.
2. Hover over any column header and click the ⚙️ gear (**Configure Table**), or right-click a column header.
3. Tick **ID** and apply.

A red **FP** button appears at the bottom right of every FortiGate page.

### 📋 Copy filtered policies

1. Filter the policy list as usual (search box, column filters, interface pair / sequence view).
2. Click **FP → Copy config of filtered policies** or press **`Alt+Shift+C`**.
3. FortiPlug scrolls through the list to collect every row (the GUI only renders what is visible), then fetches the config.
4. The result is copied to the clipboard and shown in a dialog with **Copy** and **Download** buttons.

```
config firewall policy
    edit 49
        set name "LAN-to-WAN"
        set srcintf "lan" "port3"
        set dstintf "wan1"
        ...
    next
end
```

The config comes from a configuration backup, so it matches `show` exactly. If your admin profile may not run backups, it is rebuilt from the REST API (a warning in the dialog tells you).

### 📑 Copy / paste any policy

1. **Right-click** a policy → **FortiPlug: Copy policy 49**.
2. **Right-click** the target policy → **FortiPlug: Paste 49 above X** or **… below X**.
3. FortiPlug creates the copy with a new ID, the name suffixed `_copy`, **disabled**, moves it into place and reloads the page.
4. Review the copy and enable it.

The copied policy survives page reloads, so you can also paste on **another FortiGate** — as long as the referenced interfaces and objects exist there. Pasting a policy that was copied on a different host asks for confirmation first.

### 🔀 Bulk edit interfaces

1. Select policies in the list (click / Ctrl+click) — or skip this and tick them in the dialog.
2. Open the dialog: **FP → Bulk edit source / destination interfaces**, right-click → **FortiPlug: Bulk edit interfaces…**, or **`Alt+Shift+I`**.
3. For **Source (From)** and **Destination (To)** pick a mode and tick one or more interfaces:

   | Mode | Result |
   |---|---|
   | Keep unchanged | Side is not touched |
   | Replace with | Interfaces become exactly the ticked ones |
   | Add | Ticked interfaces are added to the existing ones |
   | Remove | Ticked interfaces are removed |

4. Check the preview: old values are struck through, new values green, problems are flagged per policy.
5. Click **Apply to N policies** and confirm. Results are shown per policy; closing the dialog reloads the list.

> [!TIP]
> Interfaces that can't be used in policies — SD-WAN members, zone members, switch ports, aggregate members — are greyed out with the reason. `any` can't be combined with other interfaces.

---

### ✏️ Bulk rename policies

1. Select policies in the GUI, then open **FP → Bulk rename policies** or the corresponding right-click action. You can also tick policies in the dialog.
2. Review the generated names: `VL01-WAN (TCP80, TCP443)`. The service names come from the policy's configured service objects or groups.
3. Review **Interface aliases / groups**. The dialog starts with `x8=WAN` and `VPN_EX-ADM*=VPN_ADM`; change or remove these for your network. Exact names take precedence over wildcard rules. A trailing `*` matches a group. Several interfaces mapping to the same alias use that alias; other combinations use **VLXX**. Source and destination placeholders can be overridden separately. These settings change generated names, not the policy's interfaces.
4. Optionally enter a common software / purpose to generate `VL01-WAN_Software (TCP80, HTTPS)`. Every policy also has an individual purpose field. The priority is **individual purpose → common software → existing description (when reuse is enabled) → address objects → no purpose**. An explicitly empty individual purpose keeps the name without a purpose until **Regenerate names**. Enable **Reuse existing descriptions** to suggest purposes such as `BTA-Farm/LoopBack` from old names. Recognized service-only descriptions and generated `(Copy of …)` annotations are skipped. Existing `_Purpose` suffixes are recognized when their interface pair matches. Free-form names remain visible for manual interpretation; truncated descriptions cannot be reconstructed.
5. VIP and virtual-server destinations use `SRC-DST (VIP_externalPort-mappedPort-WANIP-target)`, for example `VL01-WAN (VIP_443-8443-203.0.113.10-10.0.0.10)` before shortening. `VIP_` appears once, including when there are several mappings. VIP groups are resolved to their members; virtual servers use each realserver's port and IP. VIPs without port forwarding use `ALL-ALL`. Incomplete mappings are flagged for manual correction.
6. The **Shared name limit** defaults to **40 characters** and can be set from 20 to 40, including 35. It is saved in the extension and also used for copied policy names. Software / purpose has priority: extra services are omitted and the remaining service text is shortened before the software name itself is shortened. Shortening uses **at most one literal dot (`.`)** per generated name, never `…`, `...` or repeated shortening groups. Full IP addresses retain their normal dots. Long VIP names prefer **destination name/IP and mapped port**, e.g. `VIP_192.168.1.192_5353`. Add a target IP alias such as `192.168.1.192=DNS01` to get `VIP_DNS01_5353`. Incoming port and WAN IP are omitted first. If the destination cannot fit, `VIP_._5353` or `VIP_5353` retains the destination port; ports and IPs are never shown as partial numeric fragments. When the header also needs shortening, all services or VIP mappings are summarized with `+N` so only the header uses a shortening dot. Parentheses, counts and ID suffixes are preserved. Hover for the full suggestion and expand **Policy details** for complete mappings. Manual names are validated against the limit. **Regenerate names** clears manual names and individual purposes.
7. **Automatically generated names preserve the complete interface pair.** It is never truncated; only the purpose and service/VIP details are shortened. **Manual name edits can override the pair**, e.g. replace `VLXX-virtual-wan-link` with `VLXX-sdwan`. Manual names are saved exactly as entered and still checked for length, unsupported characters, empty values and duplicates. If the generated pair and reserved details cannot fit, choose shorter interface aliases, a larger limit or edit the name manually. Duplicate generated names automatically get `_ID<policy-ID>`, including conflicts with policies outside the filtered list. The ID is preserved within the character limit. Manual names remain unchanged and conflicts are flagged.
8. Expand **Policy details** to compare source addresses, source/destination ISDB entries, destination objects, services, action, inspection settings and security profiles. Deny policies include **DENY** in their generated names. This helps distinguish rules with the same interfaces and VIPs but different whitelists, scanners or inspection profiles.
9. Resolve validation errors, then click **Rename N policies** and confirm. Only the policy name is written. Results appear per policy. Closing the dialog after successful changes reloads the list. VIP and VIP-group read access is required to detect destinations correctly. Interface/object aliases, object-label options, placeholders and purposes are edited per dialog; the shared character limit persists.

**Automatic address-based purposes** are enabled by default and can be switched off with **Infer an empty purpose from address objects**:

- A specific destination supplies the purpose. When there is one short source and one short destination, both are included, e.g. `lan-a_DanielPC-mail (ALL)`.
- Inferred address labels that repeat their corresponding interface are omitted. For this comparison, `LAN_`, `VLAN_` and separator differences are normalized, so interface `VLAN_VMs` and destination `LAN_VMs` do not appear twice. This does not rewrite manually entered purposes or negated address labels.
- If the destination is `all`, a specific source supplies the purpose, e.g. `lan-a_DL+TROJA (DENY, ALL)`. `all`, `all6`, `any`, `0.0.0.0/0` and `::/0` are treated as broad objects. Active named ISDB selections are also considered. Negated selections are marked `NOT_`.
- **Address object labels** removes the configured prefixes (default `H_, G_`) for display. Add exact or trailing-wildcard object aliases, e.g. `mail.example.com=mail` or `H_Server01=Server`. Exact aliases take precedence over wildcard aliases, including matches after prefix removal. Explicit alias values are kept as entered.
- FQDN object names use their first hostname label by default (`mail.example.com → mail`); switch this off to retain the domain. IPv4 and IPv6 address labels stay intact. Two short names use `A+B`; larger sets use `A+B+N`, or `FirstLongName+N`. Multiple objects with the same shortened label still show their additional count.
- Every row identifies the purpose's origin (manual, common, existing description, source, destination or both). Hover over the origin to see the full source object names. Policy details retain the full objects and VIP mappings.
- Services always come from the policy: a destination called `mail` does not change `ALL` into SMTP. Comments are shown for review and are never used to infer a purpose. `_ID…` is added only if the final generated names still collide.

## ⚙️ Configuration

| Setting | Where | Default |
|---|---|---|
| Pasted policies start disabled | `PASTE_DISABLED` in [`src/features/policy-clipboard.js`](src/features/policy-clipboard.js) | `true` |
| Policy name limit (rename and paste) | **Shared name limit** in the bulk rename dialog | `40` |
| Copy shortcut | `shortcut` in [`src/features/copy-policies.js`](src/features/copy-policies.js) | `Alt+Shift+C` |
| Bulk edit shortcut | `shortcut` in [`src/features/bulk-interfaces.js`](src/features/bulk-interfaces.js) | `Alt+Shift+I` |

After changing a file, reload the extension in `about:debugging` (or rebuild / re-sign the `.xpi`).

**Multi-VDOM:** the VDOM is taken from the GUI URL (`?vdom=…`); all API calls are scoped to it.

---

## 🩺 Troubleshooting

| Symptom | Fix |
|---|---|
| No **FP** button | Reload the FortiGate tab after installing / reloading the extension. Check FortiPlug is enabled in `about:addons`. |
| *No "ID" column found* | Enable the **ID** column (see [Prepare the policy list](#prepare-the-fortigate-policy-list-once)). |
| No FortiPlug entries in the right-click menu | ID column visible? Then run **FP → Diagnose** right after the right-click and check the `Last right-click:` line. |
| *No GUI selection detected* in bulk edit | Tick the policies in the dialog. To improve detection, run **Diagnose** with rows selected and open an issue with the `Selected in GUI` / `Row elements` lines. |
| *entry not found in datasource* | An interface isn't usable in policies on this FortiGate (member of SD-WAN, zone, switch, …). |
| *Config backup not available* | Your admin profile lacks backup permission; the output was generated from the REST API instead. |

**Diagnose** (FP button) prints everything FortiPlug detects — please include its output when opening an issue (redact names if needed).

---

## 🛠 Development

No build step, no dependencies — plain JavaScript loaded as content scripts.

```
fortiplug/
├── manifest.json               # extension manifest (MV2)
├── icons/icon.svg
├── popup/                      # toolbar popup: actions + feature list
│   ├── popup.html
│   └── popup.js
└── src/
    ├── core.js                 # feature registry, REST API (session + CSRF), UI (launcher, toast, modal)
    ├── policy-names.js         # shared name limit, purpose extraction and structured shortening
    ├── main.js                 # FortiGate detection, activation, popup messaging
    └── features/
        ├── copy-policies.js    # list detection (shared) + copy filtered policies + diagnose
        ├── policy-clipboard.js # right-click copy / paste
        ├── bulk-interfaces.js  # bulk interface editor
        └── bulk-rename.js      # bulk rename with editable preview
```

### Adding a feature

1. Create `src/features/<name>.js`:
   ```js
   (() => {
     const FP = window.FortiPlug;
     FP.register({
       id: 'my-feature',
       label: 'My feature',
       description: 'What it does (shown in the popup).',
       usage: 'Where / how to use it',
       isAvailable: () => location.pathname.includes('/firewall/'),
       run: async () => FP.toast('Hello from FortiPlug', 'ok'),
     });
   })();
   ```
2. Add it to `content_scripts.js` in `manifest.json` (before `src/main.js`).
3. Add a `<script>` tag for it in `popup/popup.html`.

Useful helpers: `FP.request` / `FP.requestJson` (REST calls with session + CSRF), `FP.getVdom()`, `FP.policyList.collectList()` (IDs + selection of the current list), `FP.showModal`, `FP.toast`, `FP.copyText`.

Run the naming and dialog regression tests with Node.js (no dependencies):

```sh
node --test tests/
```

Optionally set `FORTIPLUG_POLICY_SAMPLE` to the path of a local CLI policy excerpt to run the additional 43-policy reference check. This reads the file locally; the policy export is not included in the repository.

---

<div align="center">
<sub>Not affiliated with or endorsed by Fortinet. FortiGate and FortiOS are trademarks of Fortinet, Inc.<br>
Use at your own risk — review changes before enabling pasted or edited policies.</sub>
</div>
