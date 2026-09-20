# RunningBoard Private Value Catalog

Research snapshot: 2026-09-13
Host: macOS 26.6.2 (25G83)
Scope: installed `LifecyclePolicy` data, the current dyld-hosted RunningBoard frameworks, the Xcode 26.2 SDK stubs and private kernel headers, Apple XNU sources, and selected historical reverse-engineering references.

## Executive conclusions

`/System/Library/LifecyclePolicy/DomainAttributes/com.apple.coreos.plist` is an Apple-supplied RunningBoard policy definition. Its `reconnect` entry is gated by the private entitlement `com.apple.private.runningboard.reconnect`. It grants a fixed two-second assertion, a non-focal interactive CPU role, high coalition importance, jetsam band 40, protection against base-memory-limit reduction, and the build-scoped diagnostic reason `20212`.

The important distinction is that this plist describes policy that RunningBoard can apply. Finding it on disk does not prove that any process requested the policy, held the entitlement, received the assertion, or used the resources at a particular time.

Most named values can be decoded exactly on this build through exported `NSStringFromRBS…` functions, exported RBS-to-Darwin role conversion functions, or RunningBoard's private attribute factory. Modern `RunningReason` numbers are different: no corresponding string-conversion export was found. Their labels below are cross-references to installed `domain/policy` names, not stable public Apple enum names.

## Confidence model

- **Confirmed-current** — returned by the current framework, decoded by the current attribute factory, or present verbatim in the current signed system policy.
- **Apple-correlated** — matched to Apple XNU source or an Xcode-shipped private kernel header.
- **Cross-referenced** — a raw value is associated with the installed domain/policy that uses it; the association is exact for this build but is not a public enum contract.
- **Inferred** — behavior is supported by class/property/method names but Apple publishes no stable semantic contract.
- **Unresolved** — observed but no reliable semantic label was located.

Private framework values and method names are ABI details and can change between OS builds. EntitlementLens should always retain the raw value, source path, OS build, and confidence next to any decoded label.

## `com.apple.coreos/reconnect`

Source: `/System/Library/LifecyclePolicy/DomainAttributes/com.apple.coreos.plist`
SHA-256: `8e3dffdf2aeabc6e8793f284ace05662154a99773bb4b0d7494d60662fc4e40a`
Metadata: `root:wheel`, mode `0644`, flags `restricted,compressed`, 700 bytes.

| Attribute | Stored value | Current-build decoding | Meaning | Confidence |
|---|---|---|---|---|
| Restriction | `OriginatorEntitlement = com.apple.private.runningboard.reconnect` | Exact string | Only an originator with this private entitlement may acquire the domain attribute. | Confirmed-current |
| `RBSDurationAttribute.StartPolicy` | `RBSDurationStartPolicyFixed` | `1 = Fixed` | The lifetime starts on the fixed policy clock. | Confirmed-current |
| `WarningDuration` | `0` | `0.00` | No warning interval precedes invalidation. | Confirmed-current; unit inferred as seconds |
| `InvalidationDuration` | `2` | `2.00` | The assertion is invalidated after a two-unit interval. The API uses `NSTimeInterval`-style `Double` values and `…AfterInterval:` methods, strongly indicating seconds. | Confirmed value; seconds inferred |
| `RBSDurationAttribute.EndPolicy` | `RBSDurationEndPolicyInvalidate` | `1 = Invalidate` | Invalidate the assertion rather than terminate the target. | Confirmed-current |
| `RBSCPUAccessGrant.Role` | `RBSRoleUserInteractiveNonFocal` | RBS role `6`; Darwin role `4` | Maps to `PRIO_DARWIN_ROLE_UI_NON_FOCAL`, described by the Xcode private kernel header as on-screen, non-focal UI. | Confirmed-current and Apple-correlated |
| `RBSCoalitionLevelGrant.CoalitionLevel` | `RBSCoalitionLevelHigh` | internal value `100` | Applies the high coalition level. The precise scheduler/accounting effect is private. | Confirmed-current; effect partly inferred |
| `RBSJetsamPriorityGrant.Band` | `40` | `JETSAM_PRIORITY_MAIL`, alias `JETSAM_PRIORITY_ELEVATED_INACTIVE` | Higher bands are killed later than lower bands in many memorystatus kill paths. Apple notes that band 40 is no longer specifically Mail and is used by active background work. | Apple-correlated |
| `RBSPreserveBaseMemoryGrant` | marker attribute | `preventBaseMemoryLimitReduction` state field | Prevents reduction of the process's base memory limit; it does not specify a new memory amount. | Inferred from current runtime structure |
| `RBSRunningReasonAttribute.RunningReason` | `20212` | `com.apple.coreos/reconnect` | Assertion reason/tag associated only with this installed policy on this build. It is not the resource grant and is not a known public enum case. | Cross-referenced |

## Framework-exported enum families

The following names and numeric values were obtained by loading the current dyld-hosted `RunningBoardServices.framework` and calling its exported conversion functions in isolated processes. Empty results outside the listed cases were not promoted to values.

### Acquisition completion policy

| Value | Framework string |
|---:|---|
| 0 | `AfterValidation` |
| 1 | `AfterApplication` |

### CPU maximum-usage violation policy

| Value | Framework string |
|---:|---|
| 0 | `Log` |
| 1 | `Invalidate` |
| 2 | `InvalidateAndTerminateProcess` |

### Debug state

| Value | Framework string |
|---:|---|
| 0 | `unknown` |
| 1 | `none` |
| 2 | `ptracing` |
| 3 | `asserted` |

### Duration start and end policies

| Start value | Framework string |
|---:|---|
| 0 | `Unspecified` |
| 1 | `Fixed` |
| 2 | `Proc-Start-Relative` |
| 3 | `After-Originator-Exit` |
| 101 | `Relative` |
| 102 | `Delayed-Relative` |
| 103 | `Delayed-Fixed` |

| End value | Framework string |
|---:|---|
| 0 | `WarnOnly` |
| 1 | `Invalidate` |
| 2 | `InvalidateAndTerminateProcess` |

The installed policy spelling `RBSDurationEndPolicyTerminate` is accepted by the current attribute factory and decodes to end-policy value `2`.

### CPU roles and their Darwin roles

| RBS value | RBS string | Darwin value | Xcode private-header meaning |
|---:|---|---:|---|
| 0 | `unknown` | — | No reliable mapping promoted. |
| 1 | `None` | — | No resource role. |
| 2 | `Background` | 6 | `PRIO_DARWIN_ROLE_DARWIN_BG`: throttled background work. |
| 3 | `LaunchTAL` | 5 | `PRIO_DARWIN_ROLE_TAL_LAUNCH`: throttled launch for TAL resume. |
| 4 | `NonUserInteractive` | 3 | `PRIO_DARWIN_ROLE_NON_UI`: off-screen, non-focal UI. |
| 5 | `UserInitiated` | 7 | `PRIO_DARWIN_ROLE_USER_INIT`: off-screen user-initiated work. |
| 6 | `UserInteractiveNonFocal` | 4 | `PRIO_DARWIN_ROLE_UI_NON_FOCAL`: on-screen, non-focal UI. |
| 7 | `UserInteractive` | 2 | `PRIO_DARWIN_ROLE_UI`: on-screen UI, focus unknown. |
| 8 | `UserInteractiveFocal` | 1 | `PRIO_DARWIN_ROLE_UI_FOCAL`: on-screen, focal UI. |

### GPU roles

| Value | Framework string |
|---:|---|
| 0 | `unknown` |
| 1 | `None` |
| 2 | `Background` |
| 3 | `UserInteractive` |
| 4 | `UserInteractiveFocal` |

### Memory-limit strength

| Value | Framework string |
|---:|---|
| 0 | `Default` |
| 1 | `Hard` |
| 2 | `Soft` |

### Prevent-launch state

| Value | Framework string |
|---:|---|
| 0 | `unknown` |
| 1 | `None` |
| 2 | `Prevented` |

### Task state

| Value | Framework string |
|---:|---|
| 0 | `unknown` |
| 1 | `none` |
| 2 | `running` |
| 3 | `running-suspended` |
| 4 | `running-active` |

### Termination resistance

| Value | Framework string |
|---:|---|
| 0 | `unknown` |
| 10 | `NotRunning` |
| 20 | `None` |
| 30 | `NonInteractive` |
| 40 | `Interactive` |
| 50 | `Absolute` |

### Legacy reason values

Only values for which `NSStringFromRBSLegacyReason` returned a name are included.

| Value | Framework string |
|---:|---|
| 0 | `None` |
| 1 | `MediaPlayback` |
| 2 | `Location` |
| 3 | `ExternalAccessory` |
| 4 | `FinishTask` |
| 5 | `Bluetooth` |
| 7 | `BackgroundUI` |
| 8 | `InterAppAudioStreaming` |
| 9 | `ViewService` |
| 10 | `NewsstandDownload` |
| 12 | `VoIP` |
| 13 | `Extension` |
| 16 | `WatchConnectivity` |
| 18 | `ComplicationUpdate` |
| 19 | `WorkoutProcessing` |
| 20 | `ComplicationPushUpdate` |
| 21 | `BackgroundLocationProcessing` |
| 23 | `AudioRecording` |

Current policies do not necessarily preserve those old meanings. For example, current raw value `2` appears under `com.apple.maps/ActiveNavigation`, not a policy literally named `Location`. EntitlementLens should show both the framework's legacy name and the current installed cross-reference, with separate provenance.

### Legacy flags

`NSStringFromRBSLegacyFlags` treats these as independent bit flags.

| Bit | Framework string |
|---:|---|
| 1 | `PreventTaskSuspend` |
| 2 | `PreventTaskThrottleDown` |
| 4 | `AllowIdleSleep` |
| 8 | `WantsForegroundResourcePriority` |
| 16 | `AllowSuspendOnSleep` |
| 32 | `PreventThrottleDownUI` |

## Attribute-factory-only values

These spellings were accepted by the current private `RBAttributeFactory` and read back through the resulting object's typed property. No exported public header defines them.

| Family | Stored spelling | Decoded value |
|---|---|---:|
| Coalition level | `RBSCoalitionLevelLow` | 1 |
| Coalition level | `RBSCoalitionLevelHigh` | 100 |
| Duration start | `RBSDurationStartPolicyFixed` | 1 |
| Duration start | `RBSDurationStartPolicyProcessStartRelative` | 2 |
| Duration start | `RBSDurationStartPolicyAfterOriginatorExit` | 3 |
| Duration start | `RBSDurationStartPolicyDelayedRelative` | 102 |
| Duration end | `RBSDurationEndPolicyInvalidate` | 1 |
| Duration end | `RBSDurationEndPolicyTerminate` | 2 |
| CPU role | `RBSRoleBackground` | 2 |
| CPU role | `RBSRoleLaunchTAL` | 3 |
| CPU role | `RBSRoleNonUserInteractive` | 4 |
| CPU role | `RBSRoleUserInitiated` | 5 |
| CPU role | `RBSRoleUserInteractiveNonFocal` | 6 |
| CPU role | `RBSRoleUserInteractive` | 7 |
| CPU role | `RBSRoleUserInteractiveFocal` | 8 |
| GPU role | `RBSGPURoleBackground` | 2 |
| GPU role | `RBSGPURoleUserInteractive` | 3 |
| GPU role | `RBSGPURoleUserInteractiveFocal` | 4 |
| Termination resistance | `RBSTerminationResistanceNonInteractive` | 30 |
| Termination resistance | `RBSTerminationResistanceInteractive` | 40 |
| Memory-limit strength | `RBSMemoryLimitStrengthHard` | 1 |
| Memory-limit strength | `RBSMemoryLimitStrengthSoft` | 2 |

Runtime convenience methods also establish that `RBSJetsamPriorityGrant.grantWithBackgroundPriority` produces band 40 and `grantWithForegroundPriority` produces band 100. CPU convenience grants produce Background, NonUserInteractive, UserInteractiveNonFocal, and UserInteractiveFocal roles. The method named `grantUserInitiated` currently produces `NonUserInteractive`; because the name and result differ, the raw result should be reported without normalizing it to UserInitiated.

## Jetsam bands

Apple's XNU documentation states that memorystatus has 210 ordinary priority levels, higher numbers are more important, and many kill types traverse bands in ascending order. RunningBoard asserts bands for managed apps and daemons. The current XNU header defines these named constants:

| Band | XNU constant or alias | Note |
|---:|---|---|
| 0 | `JETSAM_PRIORITY_IDLE` | Idle. |
| 10 | `JETSAM_PRIORITY_IDLE_DEFERRED`; `AGING_BAND1` | Deferred/aging. |
| 15 | `JETSAM_PRIORITY_AGING_BAND1_STUCK` | Stuck system processes in deferred band. |
| 20 | `JETSAM_PRIORITY_BACKGROUND_OPPORTUNISTIC`; `AGING_BAND2` | Opportunistic background. |
| 30 | `JETSAM_PRIORITY_BACKGROUND` | Background. |
| 40 | `JETSAM_PRIORITY_MAIL`; `ELEVATED_INACTIVE` | Active background work; the historical Mail name is no longer literal. |
| 50 | `JETSAM_PRIORITY_PHONE` | Phone. |
| 75 | `JETSAM_PRIORITY_FREEZER` | Suspended/frozen. |
| 80 | `JETSAM_PRIORITY_UI_SUPPORT` | UI support. |
| 90 | `JETSAM_PRIORITY_FOREGROUND_SUPPORT` | Foreground support. |
| 100 | `JETSAM_PRIORITY_FOREGROUND` | Foreground. |
| 120 | `JETSAM_PRIORITY_AUDIO_AND_ACCESSORY` | Audio/accessory. |
| 130 | `JETSAM_PRIORITY_CONDUCTOR` | Conductor. |
| 150 | `JETSAM_PRIORITY_DRIVER_APPLE` | Apple driver. |
| 160 | `JETSAM_PRIORITY_HOME` | Home/SpringBoard family. |
| 170 | `JETSAM_PRIORITY_EXECUTIVE` | Executive. |
| 180 | `JETSAM_PRIORITY_IMPORTANT`; default | Important system services. |
| 190 | `JETSAM_PRIORITY_CRITICAL`; `TELEPHONY` | Critical/telephony. |
| 210 | `JETSAM_PRIORITY_MAX` | Maximum ordinary band. |
| 999 | `JETSAM_PRIORITY_INTERNAL` | Excluded from jetsam processing, used by launchd/kernel_task. |

Installed policy files on this Mac use 11 bands:

| Band | Uses | Interpretation |
|---:|---:|---|
| 20 | 2 | Named XNU opportunistic-background band. |
| 30 | 6 | Named XNU background band. |
| 33 | 1 | Unnamed intermediate value; `frontboard/Utility3`. |
| 34 | 1 | Unnamed intermediate value; `frontboard/Utility2`. |
| 35 | 2 | Unnamed intermediate value; `frontboard/Utility` and `quicklook/KeepAboveBackgroundBand`. |
| 40 | 83 | Named XNU band 40/elevated inactive. |
| 80 | 4 | Named XNU UI-support band. |
| 89 | 1 | Unnamed value immediately below foreground support; `dasd/BGContinuedProcessingTask`. |
| 90 | 5 | Named XNU foreground-support band. |
| 100 | 54 | Named XNU foreground band. |
| 101 | 1 | Unnamed value immediately above foreground; `frontboard/ForegroundFocal`. |

Names for 33, 34, 35, 89, and 101 are local policy labels, not XNU constants.

## Installed-policy scalar inventory

The scan covered 90 domain-attribute plist files plus the separate `domains.plist` index. All 90 parsed successfully. The generated inventory contains 2,447 attribute-property rows, including marker attributes that have no scalar property.

| Attribute family | Uses | Observed scalar values |
|---|---:|---|
| `RBSRunningReasonAttribute` | 229 | 124 distinct numeric values. Full occurrence-level catalog in the companion CSV. |
| `RBSCPUAccessGrant` | 202 | Background 65; NonUserInteractive 59; UserInteractiveNonFocal 40; UserInteractiveFocal 23; UserInteractive 8; LaunchTAL 5; UserInitiated 2. |
| `RBSJetsamPriorityGrant` | 160 | 11 distinct bands, detailed above. |
| `RBSCoalitionLevelGrant` | 126 | High 122; Low 4. |
| `RBSDurationAttribute` | 96 | Fixed 58; DelayedRelative 20; ProcessStartRelative 17; AfterOriginatorExit 1. End: Invalidate 91; Terminate 5. |
| `RBSResistTerminationGrant` | 98 | Interactive 52; NonInteractive 46. |
| `RBSPreserveBaseMemoryGrant` | 82 | Marker attribute. |
| `RBSBaseMemoryGrant` | 70 | Soft 67; Hard 3. Categories: Active 57 plus 13 extension/poster/widget categories. |
| `RBSGPUAccessGrant` | 64 | Background 29; UserInteractive 24; UserInteractiveFocal 11. |
| `RBSTagAttribute` | 50 | SupportsBackgroundAudio 48; SupportsContinuedBackgroundProcessing 1; FBDisableWatchdog 1. |
| `RBSPreventIdleSleepGrant` | 48 | Marker attribute. |
| `RBSEndowmentGrant` | 44 | Userfacing namespace 38; Visibility namespace 6. |
| `RBSMimicTaskSuspensionAttribute` | 35 | Marker attribute. |
| `RBSForceRoleManageAttribute` | 30 | Marker attribute. |
| `RBSSuspendableCPUGrant` | 29 | Background 10; UserInteractive 5; UserInteractiveNonFocal 4; LaunchTAL 4; UserInteractiveFocal 4; NonUserInteractive 2. |
| `RBSAcquisitionCompletionAttribute` | 25 | AfterApplication 25. |
| `RBSInvalidateUnderConditionAttribute` | 25 | Condition `therm`; thresholds 810, 820, 830, 840, 850, 860. Units/scale unresolved. |
| `RBSCPUMaximumUsageLimitation` | 13 | Percentage 80; duration 20 or 60; roles Background, NonUserInteractive, UserInitiated; policies Log, Invalidate, or InvalidateAndTerminateProcess. |
| `RBSAppNapPreventTimerThrottleGrant` | 10 | Tiers 0 through 5 are all present. Exact tier semantics unresolved. |
| `RBSDomainAttribute` | 9 | References `com.apple.frontboard` or `com.apple.common` named policy entries. |
| `RBSPersistentAttribute` | 5 | Marker attribute. |
| `RBSSavedEndowmentGrant` | 2 | BoardServices endpoint-injection namespace with two saved keys. |
| `RBSCPUMinimumUsageGrant` | 1 | 100%, NonUserInteractive, duration `4294967295`; sentinel interpretation is likely but not promoted as fact. |
| `RBSPrefetchPageAttribute` | 1 | Scenario 0; semantics unresolved. |
| `RBSDebugGrant` | 1 | Marker attribute. |
| `RBSLaunchGrant` | 1 | Marker attribute. |

Additional marker families observed are App Nap enable/inactive and prevention of background sockets, disk throttling, low-priority CPU, and suppressed CPU; relative-start-time definition; subordinate-process behavior; and compound/restriction nodes. Every occurrence and scalar property is retained in `RunningBoard-Installed-Policy-Inventory.csv` rather than duplicated here.

## RunningReason catalog

The current installed set contains 229 occurrences and 124 distinct numeric values. The complete occurrence-level table is in `RunningBoard-RunningReason-Catalog.csv`, including the raw plist type because 12 occurrences are encoded as `Real` values such as `20009.0` even though their numeric values are integral.

Useful clusters include:

| Range/value | Current installed cross-references |
|---|---|
| 1–23 | Mostly historical/legacy families: media playback, navigation/location, external accessory, finish task, view service, background download, extension, health launch, scene snapshot, location, background data fetch, audio recording. Holes remain. |
| 100–103 | DAS background task families: app refresh, unrestricted processing, restricted processing, health research/exposure notification. |
| 10000–10010 | System shell/foreground hosting, graceful/background hosting, radar/unbounded networking, underlying app, picture-in-picture, wallpaper photo update. Values are sparse. |
| 20001–20026 | Domain-specific assignments including network testing, DYLD launch, banner request, preview session, hotspot helper, CoreAudio, photo power control, test keep-alive, accessory, call services, transient task, and email wake. |
| 20201–20256 | Dense domain-specific assignments. `20210` AppleEvents Send; `20211` compass Location; `20212` coreos reconnect; `20213` user activity advertising; `20214` display-archive rendering; `20216` FrontBoard workspace reconnect. `20215` is not installed on this build. |
| 20300–20839 | Newer domain-specific assignments spanning simulator rendering, performance trace, widgets, sharing, model inference, background processing, authentication, poster rendering, page-in prefetching, and pasteboard promise fulfillment. Values remain sparse. |

`RBSRunningReasonAttribute` exposes a 64-bit `runningReason` property and `withReason:` constructor. No `NSStringFromRBSRunningReason` export was found in the current SDK stub or loaded framework. The process-state runtime exposes roles, jetsam, and memory controls but no equivalent running-reason state property. These observations support treating a modern RunningReason as assertion provenance/diagnostic classification rather than as a standalone resource privilege.

## Other RunningBoard configuration discovered

- `/System/Library/FeatureFlags/Domain/RunningBoard.plist` exposes enabled feature flags named `allow_mac_multi_instance`, `conditions`, `dynamic_memory`, `launch_angs`, `manage_all_extensions`, and `runningboard_appnap_all` on this build. A feature flag being enabled is configuration, not evidence of feature use by a particular process.
- `/System/Library/LaunchDaemons/com.apple.runningboardd.plist` defines `/usr/libexec/runningboardd`, its Mach services, Pressured Exit, and transaction behavior.
- `/System/Library/RunningBoard/runningboardEntitlementsConfiguration.plist` lists entitlement-controlled client capabilities, including primitive attributes and target-identity access. Presence in this allowlist is configuration, not proof that a client exercised the capability.
- `/System/Library/Sandbox/Profiles/com.apple.runningboard.sb` is RunningBoard's private sandbox profile and contains private-interface warnings and service rules.
- Apple XNU documents that RunningBoard manages jetsam bands and implements process-freezing opt-out for relevant services. This corroborates the framework-to-kernel relationship without making the private plist schema public API.

## EntitlementLens integration rules

1. Preserve `rawValue`, `decodedLabel`, `decoderSource`, `confidence`, `osBuild`, and `sourceFileHash` as separate fields.
2. Label current framework conversion results as build-scoped private SPI, not public SDK constants.
3. For RunningReason, display both the raw number and all installed `domain/policy` cross-references. Do not invent a single canonical name when multiple policies share the number.
4. Distinguish RBS roles from Darwin roles; retain both numeric spaces and the conversion provenance.
5. Resolve jetsam bands against Apple XNU constants, but leave unnamed intermediate bands numeric.
6. Treat duration values as raw numeric intervals unless the UI explicitly marks the seconds interpretation as inferred.
7. Report policy/configuration separately from process activity. A static entitlement or policy file establishes capability and policy, not execution.
8. Never require root merely to decode these public-readable policy files. Full Disk Access and a narrowly scoped privileged helper address different access boundaries and do not turn private schema into stable API.

## Coverage and limitations

- This is exhaustive for scalar properties in the 90 installed domain-attribute files on macOS 26.6.2 build 25G83. It is not exhaustive for policy files present only on iOS, iPadOS, watchOS, tvOS, visionOS, or other macOS builds.
- `domains.plist` names 161 possible/cross-platform domains, while only 90 domain-specific attribute files are installed here. A name in the index without a local file was not assigned invented values.
- Private framework runtime probing was limited to exported conversion functions, Objective-C class/method metadata, convenience constructors, and the private attribute factory. It did not patch RunningBoard, attach to `runningboardd`, or acquire assertions.
- Static strings and method names were used as leads, then promoted only when corroborated by a current runtime result, system plist, SDK header, or XNU source.
- The attached 16-page PDF was visually rendered and searched as a reference. No RunningBoard, LifecyclePolicy, `com.apple.coreos`, or relevant enum material was located, so it did not supply substantive values.
- Public historical class dumps and binary diffs corroborate the existence and drift of private fields and methods but are not authoritative for the current host.

## Generated evidence files

- `RunningBoard-Installed-Policy-Inventory.csv` — 2,447 occurrence-level attribute/property rows; SHA-256 `61ce691ae1e15d0d8d13ba7cf1ef0c350389c2c47f1bcea83712847d47b6f66d`.
- `RunningBoard-RunningReason-Catalog.csv` — 229 reason occurrences and 124 distinct numeric values; SHA-256 `1fca85b2432a0f5883901d4328932527041d9b877b7b352ca6f5a22fe2881c1c`.

## Sources

1. Current macOS system policies and frameworks: `/System/Library/LifecyclePolicy`, `/System/Library/PrivateFrameworks/RunningBoard.framework`, `/System/Library/PrivateFrameworks/RunningBoardServices.framework`, `/System/Library/RunningBoard`, `/System/Library/FeatureFlags/Domain/RunningBoard.plist`, and `/System/Library/Sandbox/Profiles/com.apple.runningboard.sb`.
2. Xcode 26.2 SDK private stubs and kernel header: `RunningBoard.tbd`, `RunningBoardServices.tbd`, and `Kernel.framework/Headers/sys/resource_private.h`.
3. Apple XNU, [Memorystatus Subsystem](https://github.com/apple-oss-distributions/xnu/blob/main/doc/vm/memorystatus.md).
4. Apple XNU, [`kern_memorystatus.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kern_memorystatus.h).
5. Apple XNU, [Freezer](https://github.com/apple-oss-distributions/xnu/blob/main/doc/vm/freezer.md).
6. Apple Developer Documentation, [EXC_CRASH (SIGKILL)](https://developer.apple.com/documentation/xcode/sigkill?language=objc).
7. Historical secondary reference: Limneos, [`RBSLegacyAttribute.h` class dump for iOS 16.3](https://developer.limneos.net/index.php?framework=RunningBoardServices.framework&header=RBSLegacyAttribute.h&ios=16.3).
8. Secondary binary-diff reference: blacktop, [RunningBoard iOS 26.2 framework diff](https://github.com/blacktop/ipsw-diffs/blob/main/26_2_23C5027f__vs_26_2_23C5033h/DYLIBS/RunningBoard.md).
