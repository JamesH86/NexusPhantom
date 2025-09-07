# Moto G Play 2023 Carrier Unlock Research

## Device Information
- **Model**: moto g play - 2023 (XT2271-1PP)
- **Codename**: maui
- **Carrier**: Verizon (`vzwpre`, `maui_vzw`)
- **Android Version**: 13 (API 33)
- **Build**: T3SGS33.165-46-3-1-10
- **Security Patch**: 2024-09-01
- **Bootloader**: Locked (`ro.boot.vbmeta.device_state: locked`)
- **Verified Boot**: Green state (integrity intact)

## Key Research Targets Identified

### 1. VZWRemoteSimlockService (`com.verizon.remoteSimlock`)
- **Location**: `/system/app/VZWRemoteSimlockService/`
- **Version**: 1.2 (versionCode 102)
- **Signature Protection**: `signature|privileged`
- **Custom Permission**: `com.verizon.permission.ACCESS_REMOTE_SIMLOCK`
- **Shared UID**: `mediatek.uid.rsu` (UID 10126)
- **Service Action**: `com.verizon.remoteSimlock.RSU_SERVICE`

**Research Notes**: This is the primary remote SIM unlock service. The fact it uses MediaTek shared UID suggests potential MediaTek-specific unlock mechanisms.

### 2. CarrierConfig (`com.android.carrierconfig`)
- **Location**: `/system_ext/priv-app/CarrierConfig/`
- **Permissions**: `READ_PRIVILEGED_PHONE_STATE`
- **Service**: `android.service.carrier.CarrierService`

### 3. Additional Packages Found
- `com.google.android.ims` (CarrierServices)
- `com.motorola.carriersettingsext` (CarrierSettingsExt)
- `com.motorola.msimsettings` (Multi-SIM settings)
- `com.mediatek.carrierexpress` (MediaTek carrier express)

## Security Observations

1. **Bootloader Status**: Device is fully locked with verified boot enforcing
2. **SIM Lock Architecture**: Uses Verizon's remote unlock service + MediaTek backend
3. **Permission Model**: Signature-level protection on unlock service
4. **Network Carrier**: Verizon Wireless (MCC/MNC 311480)

## Next Steps for Bug Bounty Research

1. **Static Analysis**: Decompile VZWRemoteSimlockService.apk for:
   - Hardcoded endpoints/credentials
   - Missing input validation
   - Insecure data handling
   - Exported components without proper protection

2. **Network Analysis** (if in scope):
   - Monitor unlock request traffic
   - Check for certificate pinning bypasses
   - Validate server-side authentication

3. **Runtime Analysis**:
   - Monitor logcat during unlock attempts
   - Check for sensitive data leakage
   - Analyze unlock failure responses

## Files Collected
- Device properties: `device_info.txt`
- Package dump: `vzw_simlock_analysis.txt`
- APK binaries: `VZWRemoteSimlockService.apk`, `CarrierConfig.apk`

**Status**: Ready for static analysis phase
