# SIM states: what you can do with each

What you can get out of a SIM — both **data extraction** from the card and
**Rayhunter capture/detection** — depends on two *independent* things:

1. **Card lock state** — is the SIM's PIN (CHV1) unlocked, or is it PIN/PUK-locked?
   This governs which files you can read off the card, and whether the modem can
   present the subscriber identity to a network at all.
2. **Account activation** — is there a live, provisioned subscription behind the
   IMSI? This governs whether the network lets the device *attach* (and therefore
   whether you get connected-mode and data-plane traffic).

A SIM can be any combination (e.g. unlocked-but-not-activated, or
locked-but-still-provisioned). The three cases below are the common ones.

> Rayhunter itself never needs a SIM to *run*: it reads the baseband over
> `/dev/diag`, writes QMDL, and produces GSMTAP pcaps regardless. The SIM only
> determines *what cellular traffic exists to capture*.

## Analyzer categories

The analyzers in `lib/src/analysis/` fall into three tiers by what they need:

- **Broadcast / idle** — read unauthenticated downlink from cells during scan/camp.
  Work with *any* SIM state, even none:
  `incomplete_sib`, `priority_2g_downgrade` (SIB6/7), `test_analyzer` (SIB1),
  `cell_info`, and `imsi_paging` (paging channel is broadcast; best while camped).
- **Registration / signaling** — need the device to *attempt* an attach, so it must
  be able to present an identity (unlocked card). They fire on the attach/identity/
  auth/reject/release exchange, even if the attach ultimately fails:
  `imsi_requested`, `attach_reject_storm`, `auth_anomaly`, `nas_null_cipher`,
  `connection_redirect_downgrade`, `diagnostic`.
- **Service / data** — need a fully working subscription:
  `type0_sms` (silent SMS must be routed to your live line) and any data-plane
  pcaps of your own traffic.

---

## 1. Unlocked + activated SIM (fully working)

**SIM data extraction:** Full. Every elementary file is readable — IMSI (EF_IMSI),
service provider name, USIM Service Table, phonebook, SMS, ISIM identities, etc.

**Rayhunter capture:** Everything. The device attaches, enters connected mode, and
carries data, so **all three analyzer tiers** fire and pcaps include registration,
connected-mode signaling, and data-plane traffic. This is the intended operating
mode for detecting IMSI catchers as you move between towers.

## 2. Locked SIM (PIN-blocked → PUK-locked)

The device is stuck in *limited service*: it can't present a valid identity, so it
never attaches — it only scans and camps.

**SIM data extraction:** Only files with an `ALW` (always) access condition:

- **ICCID** (EF_ICCID / 2FE2)
- **EF_DIR** (2F00) — the on-card application list (USIM / ISIM / PKCS#15 AIDs)
- **Preferred languages** (EF_PL / 2F05)
- **Administrative data** (EF_AD / 6FAD) — operation mode, MNC length

Everything PIN-protected (IMSI, SPN, service table, subscriber data) returns
`SW=6982` ("security status not satisfied"). No root trick on the modem changes
this; the lock is enforced on the card.

**Rayhunter capture:** **Broadcast / idle tier only.** You still see SIB chains,
SIB6/7 downgrade broadcasts, new-tower SIB1 sightings, and paging-channel activity
from nearby cells. You get **none** of the registration/signaling detections
(no attach = no identity request, auth, reject, or forced release) and no data-plane
pcaps. Useful for surveying the RF environment, not much else.

## 3. Non-activated SIM (unlocked card, no live subscription)

The card is fine and unlocked, but the IMSI isn't provisioned, so the network
**rejects** the attach (typical causes: #7 "GPRS services not allowed", #11 "PLMN
not allowed", #14, #15). The device connects, tries, gets rejected, and retries.

**SIM data extraction:** Full — same as case 1. Lock state, not activation, governs
card reads, and the card is unlocked, so IMSI and all files are readable.

**Rayhunter capture:** **Broadcast/idle + registration/signaling tiers.** Because
the device repeatedly *attempts* attach, you get real RRC/NAS signaling —
RRC connection setup, Attach Request, often an Identity Request, sometimes
authentication, then Attach Reject and release. That drives `imsi_requested`,
`attach_reject_storm`, `auth_anomaly`, `connection_redirect_downgrade`, and
`diagnostic`. You do **not** get the service tier (no successful connection → no
data pcaps; no live line → no `type0_sms`). In practice this is a surprisingly good
state for exercising the attach/identity/reject heuristics, since the reject loop
generates lots of signaling.

---

## Summary matrix

| Capability | Unlocked + activated | Locked (PIN/PUK) | Non-activated (unlocked) |
|---|---|---|---|
| Read ICCID / EF_DIR / EF_PL / EF_AD | ✅ | ✅ | ✅ |
| Read IMSI + subscriber files | ✅ | ❌ (`6982`) | ✅ |
| Broadcast/idle analyzers (SIB, paging) | ✅ | ✅ | ✅ |
| Registration analyzers (attach/identity/reject) | ✅ | ❌ | ✅ |
| Service analyzers (`type0_sms`) + data pcaps | ✅ | ❌ | ❌ |

## Extraction methods

- **Through the Orbic modem** (`/dev/smd7`, AT commands as root): only `AT+CRSM`
  (restricted, standardized file reads) is supported. `AT+CSIM` (raw APDUs) and
  `AT+CCHO`/`AT+CGLA` (logical channels) are disabled in firmware, so you **cannot**
  select arbitrary applets, reach the GlobalPlatform Card Manager, or read CPLC
  through the radio — only the standard SIM/USIM files above.
- **With a PC/SC smartcard reader** (SIM in a ~$10 USB reader on a PC): full APDU
  access. Read-only recon needs no card keys:
  - `GlobalPlatformPro` (`gp --info`) — CPLC (chip maker, IC/OS, fab date, serial),
    ISD AID, lifecycle.
  - `pySim` (`pySim-read.py`, `pySim-shell`) — full file-tree walk; raw APDUs to
    `SELECT` AIDs and `GET DATA`.
  - OpenSC (`opensc-tool -a` for the ATR, `pkcs15-tool` for the PKCS#15 app).
  - Installing/deleting applets or unlocking PIN-protected files still needs the
    card's GlobalPlatform/ADM keys, which the carrier holds. A PUK-locked card stays
    PUK-locked on a reader too.

## Practical note for Rayhunter

You do **not** need the SIM that came with the device, a paid line, or a specific
carrier. Any compatible, unlocked SIM restores the registration tier; a fully
activated one restores everything. A cheap prepaid SIM (mind the
[RC400L's supported bands](./orbic.md#supported-bands)) is the simplest way to get
full-capability capture without dealing with a locked or unpaid original SIM.
