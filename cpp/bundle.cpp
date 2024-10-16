#include "bundle.h"
#include "macho.h"
#include "sys/stat.h"
#include "common/base64.h"
#include "common/common.h"

ZAppBundle::ZAppBundle() {
    m_pSignAsset = nullptr;
    m_bForceSign = false;
    m_bWeakInject = false;
}

bool ZAppBundle::FindAppFolder(const string &strFolder, string &strAppFolder) {
    if (IsPathSuffix(strFolder, ".app") || IsPathSuffix(strFolder, ".appex")) {
        strAppFolder = strFolder;
        return true;
    }

    DIR *dir = opendir(strFolder.c_str());
    if (nullptr != dir) {
        dirent *ptr = readdir(dir);
        while (nullptr != ptr) {
            if (0 != strcmp(ptr->d_name, ".") && 0 != strcmp(ptr->d_name, "..") &&
                0 != strcmp(ptr->d_name, "__MACOSX")) {
                bool isdir = false;
                if (DT_DIR == ptr->d_type) {
                    isdir = true;
                } else if (DT_UNKNOWN == ptr->d_type) {
                    // Entry type can be unknown depending on the underlying file system
                    ZLog::DebugV(">>> Unknown directory entry type for %s, falling back to POSIX-compatible check\n",
                                 strFolder.c_str());
                    struct stat statbuf{};
                    stat(strFolder.c_str(), &statbuf);
                    if (S_ISDIR(statbuf.st_mode)) {
                        isdir = true;
                    }
                }
                if (isdir) {
                    string strSubFolder = strFolder;
                    strSubFolder += "/";
                    strSubFolder += ptr->d_name;
                    if (FindAppFolder(strSubFolder, strAppFolder)) {
                        return true;
                    }
                }
            }
            ptr = readdir(dir);
        }
        closedir(dir);
    }
    return false;
}

bool ZAppBundle::GetSignFolderInfo(const string &strFolder, JValue &jvNode, bool bGetName) {
    JValue jvInfo;
    string strInfoPlistData;
    string strInfoPlistPath = strFolder + "/Info.plist";
    ReadFile(strInfoPlistPath.c_str(), strInfoPlistData);
    jvInfo.readPList(strInfoPlistData);
    string strBundleId = jvInfo["CFBundleIdentifier"];
    string strBundleExe = jvInfo["CFBundleExecutable"];
    string strBundleVersion = jvInfo["CFBundleVersion"];
    if (strBundleId.empty() || strBundleExe.empty()) {
        return false;
    }

    string strInfoPlistSHA1Base64;
    string strInfoPlistSHA256Base64;
    SHASumBase64(strInfoPlistData, strInfoPlistSHA1Base64, strInfoPlistSHA256Base64);

    jvNode["bid"] = strBundleId;
    jvNode["bver"] = strBundleVersion;
    jvNode["exec"] = strBundleExe;
    jvNode["sha1"] = strInfoPlistSHA1Base64;
    jvNode["sha2"] = strInfoPlistSHA256Base64;

    if (bGetName) {
        string strBundleName = jvInfo["CFBundleDisplayName"];
        if (strBundleName.empty()) {
            strBundleName = jvInfo["CFBundleName"].asCString();
        }
        jvNode["name"] = strBundleName;
    }

    return true;
}

bool ZAppBundle::GetObjectsToSign(const string &strFolder, JValue &jvInfo) {
    DIR *dir = opendir(strFolder.c_str());
    if (nullptr != dir) {
        dirent *ptr = readdir(dir);
        while (nullptr != ptr) {
            if (0 != strcmp(ptr->d_name, ".") && 0 != strcmp(ptr->d_name, "..")) {
                string strNode = strFolder + "/" + ptr->d_name;
                if (DT_DIR == ptr->d_type) {
                    if (IsPathSuffix(strNode, ".app") || IsPathSuffix(strNode, ".appex") ||
                        IsPathSuffix(strNode, ".framework") || IsPathSuffix(strNode, ".xctest")) {
                        JValue jvNode;
                        jvNode["path"] = strNode.substr(m_strAppFolder.size() + 1);
                        if (GetSignFolderInfo(strNode, jvNode)) {
                            if (GetObjectsToSign(strNode, jvNode)) {
                                jvInfo["folders"].push_back(jvNode);
                            }
                        }
                    } else {
                        GetObjectsToSign(strNode, jvInfo);
                    }
                } else if (DT_REG == ptr->d_type) {
                    if (IsPathSuffix(strNode, ".dylib")) {
                        jvInfo["files"].push_back(strNode.substr(m_strAppFolder.size() + 1));
                    }
                }
            }
            ptr = readdir(dir);
        }
        closedir(dir);
    }
    return true;
}

void ZAppBundle::GetFolderFiles(const string &strFolder, const string &strBaseFolder, set<string> &setFiles) {
    DIR *dir = opendir(strFolder.c_str());
    if (nullptr != dir) {
        dirent *ptr = readdir(dir);
        while (nullptr != ptr) {
            if (0 != strcmp(ptr->d_name, ".") && 0 != strcmp(ptr->d_name, "..")) {
                string strNode = strFolder;
                strNode += "/";
                strNode += ptr->d_name;
                if (DT_DIR == ptr->d_type) {
                    GetFolderFiles(strNode, strBaseFolder, setFiles);
                } else if (DT_REG == ptr->d_type) {
                    setFiles.insert(strNode.substr(strBaseFolder.size() + 1));
                }
            }
            ptr = readdir(dir);
        }
        closedir(dir);
    }
}

bool ZAppBundle::GenerateCodeResources(const string &strFolder, JValue &jvCodeRes) {
    jvCodeRes.clear();

    set<string> setFiles;
    GetFolderFiles(strFolder, strFolder, setFiles);

    JValue jvInfo;
    string strInfoPlistPath = strFolder + "/Info.plist";
    jvInfo.readPListFile(strInfoPlistPath.c_str());
    string strBundleExe = jvInfo["CFBundleExecutable"];
    setFiles.erase(strBundleExe);
    setFiles.erase("_CodeSignature/CodeResources");

    jvCodeRes["files"] = JValue(JValue::E_OBJECT);
    jvCodeRes["files2"] = JValue(JValue::E_OBJECT);

    for (auto strKey: setFiles) {
        string strFile = strFolder + "/" + strKey;
        string strFileSHA1Base64;
        string strFileSHA256Base64;
        SHASumBase64File(strFile.c_str(), strFileSHA1Base64, strFileSHA256Base64);

        bool bomit1 = false;
        bool bomit2 = false;

        if ("Info.plist" == strKey || "PkgInfo" == strKey) {
            bomit2 = true;
        }

        if (IsPathSuffix(strKey, ".DS_Store")) {
            bomit2 = true;
        }

        if (IsPathSuffix(strKey, ".lproj/locversion.plist")) {
            bomit1 = true;
            bomit2 = true;
        }

        if (!bomit1) {
            if (string::npos != strKey.rfind(".lproj/")) {
                jvCodeRes["files"][strKey]["hash"] = "data:" + strFileSHA1Base64;
                jvCodeRes["files"][strKey]["optional"] = true;
            } else {
                jvCodeRes["files"][strKey] = "data:" + strFileSHA1Base64;
            }
        }

        if (!bomit2) {
            jvCodeRes["files2"][strKey]["hash"] = "data:" + strFileSHA1Base64;
            jvCodeRes["files2"][strKey]["hash2"] = "data:" + strFileSHA256Base64;
            if (string::npos != strKey.rfind(".lproj/")) {
                jvCodeRes["files2"][strKey]["optional"] = true;
            }
        }
    }

    jvCodeRes["rules"]["^.*"] = true;
    jvCodeRes["rules"]["^.*\\.lproj/"]["optional"] = true;
    jvCodeRes["rules"]["^.*\\.lproj/"]["weight"] = 1000.0;
    jvCodeRes["rules"]["^.*\\.lproj/locversion.plist$"]["omit"] = true;
    jvCodeRes["rules"]["^.*\\.lproj/locversion.plist$"]["weight"] = 1100.0;
    jvCodeRes["rules"]["^Base\\.lproj/"]["weight"] = 1010.0;
    jvCodeRes["rules"]["^version.plist$"] = true;

    jvCodeRes["rules2"]["^.*"] = true;
    jvCodeRes["rules2"][".*\\.dSYM($|/)"]["weight"] = 11.0;
    jvCodeRes["rules2"]["^(.*/)?\\.DS_Store$"]["omit"] = true;
    jvCodeRes["rules2"]["^(.*/)?\\.DS_Store$"]["weight"] = 2000.0;
    jvCodeRes["rules2"]["^.*\\.lproj/"]["optional"] = true;
    jvCodeRes["rules2"]["^.*\\.lproj/"]["weight"] = 1000.0;
    jvCodeRes["rules2"]["^.*\\.lproj/locversion.plist$"]["omit"] = true;
    jvCodeRes["rules2"]["^.*\\.lproj/locversion.plist$"]["weight"] = 1100.0;
    jvCodeRes["rules2"]["^Base\\.lproj/"]["weight"] = 1010.0;
    jvCodeRes["rules2"]["^Info\\.plist$"]["omit"] = true;
    jvCodeRes["rules2"]["^Info\\.plist$"]["weight"] = 20.0;
    jvCodeRes["rules2"]["^PkgInfo$"]["omit"] = true;
    jvCodeRes["rules2"]["^PkgInfo$"]["weight"] = 20.0;
    jvCodeRes["rules2"]["^embedded\\.provisionprofile$"]["weight"] = 20.0;
    jvCodeRes["rules2"]["^version\\.plist$"]["weight"] = 20.0;

    return true;
}

void ZAppBundle::GetChangedFiles(JValue &jvNode, vector<string> &arrChangedFiles) {
    if (jvNode.has("files")) {
        for (size_t i = 0; i < jvNode["files"].size(); i++) {
            arrChangedFiles.push_back(jvNode["files"][i]);
        }
    }

    if (jvNode.has("folders")) {
        for (size_t i = 0; i < jvNode["folders"].size(); i++) {
            JValue &jvSubNode = jvNode["folders"][i];
            GetChangedFiles(jvSubNode, arrChangedFiles);
            string strPath = jvSubNode["path"];
            arrChangedFiles.push_back(strPath + "/_CodeSignature/CodeResources");
            arrChangedFiles.push_back(strPath + "/" + jvSubNode["exec"].asString());
        }
    }
}

void ZAppBundle::GetNodeChangedFiles(JValue &jvNode) {
    if (jvNode.has("folders")) {
        for (size_t i = 0; i < jvNode["folders"].size(); i++) {
            GetNodeChangedFiles(jvNode["folders"][i]);
        }
    }

    vector<string> arrChangedFiles;
    GetChangedFiles(jvNode, arrChangedFiles);
    for (const auto &arrChangedFile: arrChangedFiles) {
        jvNode["changed"].push_back(arrChangedFile);
    }

    if ("/" == jvNode["path"]) { //root
        jvNode["changed"].push_back("embedded.mobileprovision");
    }
}

bool ZAppBundle::SignNode(JValue &jvNode, bool sign) {
    if (jvNode.has("folders")) {
        for (size_t i = 0; i < jvNode["folders"].size(); i++) {
            if (!SignNode(jvNode["folders"][i], sign)) {
                return false;
            }
        }
    }

    if (jvNode.has("files")) {
        for (size_t i = 0; i < jvNode["files"].size(); i++) {
            const char *szFile = jvNode["files"][i].asCString();
            ZMachO macho;
            if (!macho.InitV("%s/%s", m_strAppFolder.c_str(), szFile)) {
                return false;
            }
            if (!sign) {
                return true;
            }
            if (!macho.Sign(m_pSignAsset, m_bForceSign, "", "", "", "")) {
                return false;
            }
        }
    }

    ZBase64 b64;
    string strInfoPlistSHA1;
    string strInfoPlistSHA256;
    string strFolder = jvNode["path"];
    string strBundleId = jvNode["bid"];
    string strBundleExe = jvNode["exec"];
    b64.Decode(jvNode["sha1"].asCString(), strInfoPlistSHA1);
    b64.Decode(jvNode["sha2"].asCString(), strInfoPlistSHA256);
    if (strBundleId.empty() || strBundleExe.empty() || strInfoPlistSHA1.empty() || strInfoPlistSHA256.empty()) {
        ZLog::ErrorV(
                "Can't Get BundleID or BundleExecute or Info.plist SHASum in Info.plist! %s\n",
                strFolder.c_str());
        return false;
    }

    string strBaseFolder = m_strAppFolder;
    if ("/" != strFolder) {
        strBaseFolder += "/";
        strBaseFolder += strFolder;
    }

    string strExePath = strBaseFolder + "/" + strBundleExe;

    if (m_show_log) {
        ZLog::PrintV("签名目录:\t(%s, [%s])\n",
                     ("/" == strFolder) ? basename((char *) m_strAppFolder.c_str()) : strFolder.c_str(),
                     strBundleExe.c_str());
    }

    ZMachO macho;
    if (!macho.Init(strExePath.c_str())) {
        ZLog::ErrorV("Can't Parse BundleExecute File! %s\n", strExePath.c_str());
        return false;
    }

    CreateFolderV("%s/_CodeSignature", strBaseFolder.c_str());
    string strCodeResFile = strBaseFolder + "/_CodeSignature/CodeResources";

    JValue jvCodeRes;
    if (!m_bForceSign) {
        jvCodeRes.readPListFile(strCodeResFile.c_str());
    }

    if (m_bForceSign || jvCodeRes.isNull()) { //create
        if (!GenerateCodeResources(strBaseFolder, jvCodeRes)) {
            ZLog::ErrorV("from sign.ipadump.com>>> Create CodeResources Failed! %s\n", strBaseFolder.c_str());
            return false;
        }
    } else if (jvNode.has("changed")) { //use existsed
        for (size_t i = 0; i < jvNode["changed"].size(); i++) {
            string strFile = jvNode["changed"][i].asCString();
            string strRealFile = m_strAppFolder + "/" + strFile;

            string strFileSHA1Base64;
            string strFileSHA256Base64;
            if (!SHASumBase64File(strRealFile.c_str(), strFileSHA1Base64, strFileSHA256Base64)) {
                ZLog::ErrorV("Can't Get Changed File SHASumBase64! %s", strFile.c_str());
                return false;
            }

            string strKey = strFile;
            if ("/" != strFolder) {
                strKey = strFile.substr(strFolder.size() + 1);
            }
            jvCodeRes["files"][strKey] = "data:" + strFileSHA1Base64;
            jvCodeRes["files2"][strKey]["hash"] = "data:" + strFileSHA1Base64;
            jvCodeRes["files2"][strKey]["hash2"] = "data:" + strFileSHA256Base64;

            ZLog::DebugV("\t\tChanged File: %s, %s\n", strFileSHA1Base64.c_str(), strKey.c_str());
        }
    }

    string strCodeResData;
    jvCodeRes.writePList(strCodeResData);
    if (!WriteFile(strCodeResFile.c_str(), strCodeResData)) {
        ZLog::ErrorV("\tWriting CodeResources Failed! %s\n", strCodeResFile.c_str());
        return false;
    }

    bool bForceSign = m_bForceSign;
    if ("/" == strFolder && !dylibPaths.empty()) {
        for (auto &fPath: dylibPaths) {
            if (m_show_log) {
                ZLog::PrintV("插件注入:\t%s\n", fPath.c_str());
            }
            macho.InjectDyLib(m_bWeakInject, fPath.c_str(), bForceSign, m_show_log);
        }
    }

    if ("/" == strFolder && !removeDylibPaths.empty()) {
        for (auto &fPath: removeDylibPaths) {
            if (m_show_log) {
                ZLog::PrintV("插件移除:\t%s\n", fPath.c_str());
            }
            if (macho.RemoveDyLib(fPath.c_str(), m_show_log)) {
                ZLog::WarnV("插件移除成功:\t%s\n", fPath.c_str());
            }
        }
    }
//    if ("/" == strFolder && !m_strDyLibPath.empty()) { //inject dylib
//        macho.InjectDyLib(m_bWeakInject, m_strDyLibPath.c_str(), bForceSign);
//    }

    if (!sign) {
        return true;
    }
    if (!macho.Sign(m_pSignAsset, bForceSign, strBundleId, strInfoPlistSHA1, strInfoPlistSHA256, strCodeResData)) {
        return false;
    }

    return true;
}

void ZAppBundle::GetPlugIns(const string &strFolder, vector<string> &arrPlugIns) {
    DIR *dir = opendir(strFolder.c_str());
    if (nullptr != dir) {
        dirent *ptr = readdir(dir);
        while (nullptr != ptr) {
            if (0 != strcmp(ptr->d_name, ".") && 0 != strcmp(ptr->d_name, "..")) {
                if (DT_DIR == ptr->d_type) {
                    string strSubFolder = strFolder;
                    strSubFolder += "/";
                    strSubFolder += ptr->d_name;
                    if (IsPathSuffix(strSubFolder, ".app") || IsPathSuffix(strSubFolder, ".appex")) {
                        arrPlugIns.push_back(strSubFolder);
                    }
                    GetPlugIns(strSubFolder, arrPlugIns);
                }
            }
            ptr = readdir(dir);
        }
        closedir(dir);
    }
}

void ZAppBundle::DisableLog() {
    m_show_log = false;
}

bool ZAppBundle::SignFolder(ZSignAsset *pSignAsset,
                            const string &strFolder,
                            const string &strBundleID,
                            const string &strBundleVersion,
                            const string &strDisplayName,
                            const string &strIconPath,
                            const string &strDyLibFile,
                            const string &strDylibPrefix,
                            const string &removeDylibPath,
                            bool deletePlugIns,
                            bool deleteWatchPlugins,
                            bool deleteDeviceSupport,
                            bool deleteSchemeUrl,
                            bool enableFileAccess,
                            bool sign,
                            bool bForce,
                            bool bWeakInject,
                            bool bEnableCache) {
    m_bForceSign = bForce;
    m_pSignAsset = pSignAsset;
    m_bWeakInject = bWeakInject;
    if (nullptr == m_pSignAsset) {
        throw "签名目录初始化为空";
    }
    if (!FindAppFolder(strFolder, m_strAppFolder)) {
        if (m_show_log) {
            ZLog::ErrorV("找不到应用目录 %s\n", strFolder.c_str());
        }
        throw "找不到应用目录 " + strFolder;
    }

    if (!strBundleID.empty() || !strIconPath.empty() || !strDisplayName.empty() ||
        !strBundleVersion.empty()) { //modify bundle id
        JValue jvInfoPlist;
        if (jvInfoPlist.readPListPath("%s/Info.plist", m_strAppFolder.c_str())) {

            if (deletePlugIns) {
                vector<string> arrPlugIns;
                GetPlugIns(m_strAppFolder, arrPlugIns);
                for (auto &strPlugin: arrPlugIns) {
                    if (m_show_log) {
                        ZLog::PrintV("删除PlugIns插件: %s\n", strPlugin.c_str());
                    }
                    RemoveFolder(strPlugin.c_str());
                }
            }

            if (deleteWatchPlugins) {
                string watchPath = m_strAppFolder + "/Watch";
                //清空手表插件，保留目录
                if (IsFolderExists(watchPath)) {
                    vector<string> arrWatchPlugIns;
                    GetPlugIns(watchPath, arrWatchPlugIns);
                    for (auto &strPlugin: arrWatchPlugIns) {
                        if (m_show_log) {
                            ZLog::PrintV("删除Watch手表插件: %s\n", strPlugin.c_str());
                        }
                        RemoveFolder(strPlugin.c_str());
                    }
                }
            }


            m_bForceSign = true;
            if (!strBundleID.empty()) {
                string strOldBundleID = jvInfoPlist["CFBundleIdentifier"];//原始BundleID
                jvInfoPlist["CFBundleIdentifier"] = strBundleID;//新BundleID
                if (m_show_log) {
                    ZLog::PrintV("BundleId: %s -> %s\n", strOldBundleID.c_str(),
                                 strBundleID.c_str());
                }

                //modify plugins bundle id
                vector<string> arrPlugIns;
                GetPlugIns(m_strAppFolder, arrPlugIns);
                for (auto &strPlugin: arrPlugIns) {
                    JValue jvPlugInInfoPlist;
                    if (jvPlugInInfoPlist.readPListPath("%s/Info.plist", strPlugin.c_str())) {
                        string strOldPlugInBundleID = jvPlugInInfoPlist["CFBundleIdentifier"];
                        string strNewPlugInBundleID = strOldPlugInBundleID;
                        StringReplace(strNewPlugInBundleID, strOldBundleID, strBundleID);
                        jvPlugInInfoPlist["CFBundleIdentifier"] = strNewPlugInBundleID;
                        if (m_show_log) {
                            ZLog::PrintV("AppBundleId: %s -> %s, PlugIn\n",
                                         strOldPlugInBundleID.c_str(),
                                         strNewPlugInBundleID.c_str());
                        }
                        if (jvPlugInInfoPlist.has("WKCompanionAppBundleIdentifier")) {
                            string strOldWKCBundleID = jvPlugInInfoPlist["WKCompanionAppBundleIdentifier"];
                            string strNewWKCBundleID = strOldWKCBundleID;
                            StringReplace(strNewWKCBundleID, strOldBundleID, strBundleID);
                            jvPlugInInfoPlist["WKCompanionAppBundleIdentifier"] = strNewWKCBundleID;
                            if (m_show_log) {
                                ZLog::PrintV(
                                        "AppBundleId: %s -> %s, PlugIn-WKCompanionAppBundleIdentifier\n",
                                        strOldWKCBundleID.c_str(), strNewWKCBundleID.c_str());
                            }
                        }

                        if (jvPlugInInfoPlist.has("NSExtension")) {
                            if (jvPlugInInfoPlist["NSExtension"].has("NSExtensionAttributes")) {
                                if (jvPlugInInfoPlist["NSExtension"]["NSExtensionAttributes"].has(
                                        "WKAppBundleIdentifier")) {
                                    string strOldWKBundleID = jvPlugInInfoPlist["NSExtension"]["NSExtensionAttributes"]["WKAppBundleIdentifier"];
                                    string strNewWKBundleID = strOldWKBundleID;
                                    StringReplace(strNewWKBundleID, strOldBundleID, strBundleID);
                                    jvPlugInInfoPlist["NSExtension"]["NSExtensionAttributes"]["WKAppBundleIdentifier"] = strNewWKBundleID;
                                    if (m_show_log) {
                                        ZLog::PrintV(
                                                "AppBundleId: %s -> %s, NSExtension-NSExtensionAttributes-WKAppBundleIdentifier\n",
                                                strOldWKBundleID.c_str(), strNewWKBundleID.c_str());
                                    }
                                }
                            }
                        }
                        jvPlugInInfoPlist.writePListPath("%s/Info.plist", strPlugin.c_str());
                    }
                }
            }

            if (!strDisplayName.empty()) {
                string strOldDisplayName = jvInfoPlist["CFBundleDisplayName"];
                if (strOldDisplayName.empty()) {
                    strOldDisplayName = jvInfoPlist["CFBundleName"].asString();
                }
                jvInfoPlist["CFBundleName"] = strDisplayName;
                jvInfoPlist["CFBundleDisplayName"] = strDisplayName;
                if (m_show_log) {
                    ZLog::PrintV("AppBundleName修改: %s -> %s\n", strOldDisplayName.c_str(),
                                 strDisplayName.c_str());
                }
            }

            if (!strIconPath.empty()) {
                if (!IsFileExists(strIconPath.c_str())) {
                    if (m_show_log) {
                        ZLog::ErrorV("> 找不到Icon图标文件 %s\n", strIconPath.c_str());
                    }
                    throw "找不到Icon图标文件";
                }

                //只能使用png图片，其它格式的图片显示不了
                string iconName = "AppNewIcon";
                string iconDestPath = m_strAppFolder + "/" + iconName + ".png";
                if (CopyFile(strIconPath, iconDestPath)) {
                    if (m_show_log) {
                        ZLog::PrintV("图标复制 %s -> %s\n", strIconPath.c_str(), iconDestPath.c_str());
                    }
                }

                vector<string> arrIconFiles;
                arrIconFiles.push_back("CFBundleIcons");
                arrIconFiles.push_back("CFBundleIcons~ipad");

                for (auto &iconType: arrIconFiles) {
                    auto &app_dict = jvInfoPlist[iconType];
                    auto &bundlePrimaryIcon = app_dict["CFBundlePrimaryIcon"];
                    if (bundlePrimaryIcon.isNull()) {
                        bundlePrimaryIcon = app_dict["UINewsstandIcon"];
                    }
                    auto &iconFiles = bundlePrimaryIcon["CFBundleIconFiles"];
                    if (iconFiles.isNull()) {
                        iconFiles = bundlePrimaryIcon["CFBundleIconFiles"];
                    }
                    string strOldIconName = iconFiles[0].asString();
                    iconFiles = JValue(JValue::E_ARRAY);
                    iconFiles.push_back(iconName);
                    jvInfoPlist[iconType] = app_dict;
                    if (m_show_log) {
                        ZLog::PrintV("%s图标修改: %s -> %s\n", iconType.c_str(), strOldIconName.c_str(),
                                     (iconName + ".png").c_str());
                    }
                }
            }
            if (deleteDeviceSupport) {
                //MinimumOSVersion 10.0
                jvInfoPlist["MinimumOSVersion"] = "10.0";
            }

            if (deleteSchemeUrl) {
                jvInfoPlist["CFBundleURLTypes"] = JValue(JValue::E_ARRAY);
            }

            if (enableFileAccess) {
                jvInfoPlist["UIFileSharingEnabled"] = true;
                jvInfoPlist["UISupportsDocumentBrowser"] = true;
            }

            if (!strBundleVersion.empty()) {
                string strOldBundleVersion = jvInfoPlist["CFBundleShortVersionString"];
                jvInfoPlist["CFBundleShortVersionString"] = strBundleVersion;
                if (m_show_log) {
                    ZLog::PrintV("AppBundleVersion版本修改: %s -> %s\n", strOldBundleVersion.c_str(),
                                 strBundleVersion.c_str());
                }
            }
            jvInfoPlist.writePListPath("%s/Info.plist", m_strAppFolder.c_str());
        } else {
            if (m_show_log) {
                ZLog::ErrorV("应用中找不到 Info.plist 文件 %s\n", strFolder.c_str());
            }
            throw "应用中找不到 Info.plist 文件 " + strFolder;
        }
    }

    if (!strDisplayName.empty()) {
        m_bForceSign = true;
        JValue jvInfoPlistStrings;
        if (jvInfoPlistStrings.readPListPath("%s/zh_CN.lproj/InfoPlist.strings", m_strAppFolder.c_str())) {
            jvInfoPlistStrings["CFBundleName"] = strDisplayName;
            jvInfoPlistStrings["CFBundleDisplayName"] = strDisplayName;
            jvInfoPlistStrings.writePListPath("%s/zh_CN.lproj/InfoPlist.strings", m_strAppFolder.c_str());
        }
        jvInfoPlistStrings.clear();
        if (jvInfoPlistStrings.readPListPath("%s/zh-Hans.lproj/InfoPlist.strings", m_strAppFolder.c_str())) {
            jvInfoPlistStrings["CFBundleName"] = strDisplayName;
            jvInfoPlistStrings["CFBundleDisplayName"] = strDisplayName;
            jvInfoPlistStrings.writePListPath("%s/zh-Hans.lproj/InfoPlist.strings", m_strAppFolder.c_str());
        }
    }

    if (!WriteFile(pSignAsset->m_strProvisionData, "%s/embedded.mobileprovision",
                   m_strAppFolder.c_str())) { //embedded.mobileprovision
        if (m_show_log) {
            ZLog::ErrorV("embedded.mobileprovision 文件无法写入数据!\n");
        }
        throw "embedded.mobileprovision 文件无法写入数据";
    }
//    if (!strDyLibFile.empty()) { //inject dylib
//        string strDyLibData;
//        ReadFile(strDyLibFile.c_str(), strDyLibData);
//        if (!strDyLibData.empty()) {
//            ZLog::PrintV("---------%s",strDyLibData.c_str());
//            string strFileName = basename((char *) strDyLibFile.c_str());
//            if (WriteFile(strDyLibData, "%s/%s", m_strAppFolder.c_str(), strFileName.c_str())) {
//                StringFormat(m_strDyLibPath, "@executable_path/%s", strFileName.c_str());
//            }
//        }
//    }


    if (!strDyLibFile.empty()) { //inject dylib
        set<string> dyLibsFiles;
        if (IsFolder(strDyLibFile)) {
            DIR *dir = opendir(strDyLibFile.c_str());
            if (nullptr != dir) {
                dirent *ptr = readdir(dir);
                while (nullptr != ptr) {
                    if (0 != strcmp(ptr->d_name, ".") && 0 != strcmp(ptr->d_name, "..")) {
                        string strNode = strDyLibFile;
                        strNode += "/";
                        strNode += ptr->d_name;
                        if (DT_REG == ptr->d_type) {
                            dyLibsFiles.insert(strNode);
                        }
                    }
                    ptr = readdir(dir);
                }
                closedir(dir);
                for (auto &file: dyLibsFiles) {
                    string strDyLibData;
                    ReadFile(file.c_str(), strDyLibData);
                    if (!strDyLibData.empty()) {
                        string strFileName = basename((char *) file.c_str());
                        if (WriteFile(strDyLibData, "%s/%s", m_strAppFolder.c_str(), strFileName.c_str())) {
                            if (m_show_log) {
                                ZLog::PrintV("插件注入 %s\n", file.c_str());
                            }
                            string tmpDyLibPath;
                            StringFormat(tmpDyLibPath, "%s%s", strDylibPrefix.c_str(),
                                         strFileName.c_str());
                            dylibPaths.insert(tmpDyLibPath);
                        }
                    }
                }
            }
        } else if (IsFileExists(strDyLibFile.c_str())) {
            string strDyLibData;
            ReadFile(strDyLibFile.c_str(), strDyLibData);
            if (!strDyLibData.empty()) {
                string strFileName = basename((char *) strDyLibFile.c_str());
                if (WriteFile(strDyLibData, "%s/%s", m_strAppFolder.c_str(), strFileName.c_str())) {
                    if (m_show_log) {
                        ZLog::PrintV("Inject:\t%s\n", strDyLibFile.c_str());
                    }
                    string tmpDyLibPath;
                    StringFormat(tmpDyLibPath, "%s%s", strDylibPrefix.c_str(), strFileName.c_str());
                    dylibPaths.insert(tmpDyLibPath);
                }
            }
        } else if (!strDyLibFile.empty() && strDyLibFile.find(',') != string::npos) {
            vector<string> dyLibs;
            StringSplit(strDyLibFile, ",", dyLibs);
            for (auto &file: dyLibs) {
                string strDyLibData;
                ReadFile(file.c_str(), strDyLibData);
                if (!strDyLibData.empty()) {
                    string strFileName = basename((char *) file.c_str());
                    if (WriteFile(strDyLibData, "%s/%s", m_strAppFolder.c_str(), strFileName.c_str())) {
                        if (m_show_log) {
                            ZLog::PrintV("Inject:\t%s\n", file.c_str());
                        }
                        string tmpDyLibPath;
                        StringFormat(tmpDyLibPath, "%s%s", strDylibPrefix.c_str(), strFileName.c_str());
                        dylibPaths.insert(tmpDyLibPath);
                    }
                }
            }
        }
    }

    //将removeDylibPath以逗号分隔的字符串转换为vector给removeDylibPaths
    if (!removeDylibPath.empty()) {
        vector<string> removeDylibPathVec;
        StringSplit(removeDylibPath, ",", removeDylibPathVec);
        for (auto &file: removeDylibPathVec) {
            removeDylibPaths.insert(file);
        }
    }

    string strCacheName;
    SHA1Text(m_strAppFolder, strCacheName);
//    if (!IsFileExistsV("./.zsign_cache/%s.json", strCacheName.c_str())) {
//        m_bForceSign = true;
//    }

    JValue jvRoot;
//    if (m_bForceSign) {
    jvRoot["path"] = "/";
    jvRoot["root"] = m_strAppFolder;
    if (!GetSignFolderInfo(m_strAppFolder, jvRoot, true)) {
        if (m_show_log) {
            ZLog::ErrorV(
                    "Can't Get BundleID, BundleVersion, or BundleExecute in Info.plist! %s\n",
                    m_strAppFolder.c_str());
        }
        throw "Info.plist 文件中无法获取BundleID,BundleVersion或者BundleExecute";
    }
    auto a = jvRoot["files"];
    if (!GetObjectsToSign(m_strAppFolder, jvRoot)) {
        return false;
    }
    GetNodeChangedFiles(jvRoot);
//    } else {
//        jvRoot.readPath("./.zsign_cache/%s.json", strCacheName.c_str());
//    }

    if (m_show_log) {
        ZLog::PrintV("Signing: \t%s\n", m_strAppFolder.c_str());
        ZLog::PrintV("AppName: \t%s\n", jvRoot["name"].asCString());
        ZLog::PrintV("AppBundleId: \t%s\n", jvRoot["bid"].asCString());
        ZLog::PrintV("AppBundleVersion: \t%s\n", jvRoot["bver"].asCString());
        ZLog::PrintV("TeamId: \t%s\n", m_pSignAsset->m_strTeamId.c_str());
        ZLog::PrintV("SubjectCN: \t%s\n", m_pSignAsset->m_strSubjectCN.c_str());
        ZLog::PrintV("ReadCache: \t%s\n", m_bForceSign ? "NO" : "YES");
    }
    if (SignNode(jvRoot, sign)) {
//        if (bEnableCache) {
//            CreateFolder("./.zsign_cache");
//            jvRoot.styleWritePath("./.zsign_cache/%s.json", strCacheName.c_str());
//        }
        return true;
    }
    return false;
}
