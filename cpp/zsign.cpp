//
// Created by lake on 2024/2/2.
//
#include "common/common.h"
#include "common/json.h"
#include "openssl.h"
#include "macho.h"
#include "bundle.h"
#include <getopt.h>
#include "zsign.h"
#include <iostream>
#include <string>

using namespace std;

void sign_ipa(
        const char *c_ipaPath,//签名的ipa路径
        const char *c_p12Path,//签名的p12路径
        const char *c_p12Password,//p12密码
        const char *c_mpPath,//mobileprovision路径
        const char *c_dylibFilePath,//dylib路径,目录也可以
        const char *c_dylibPrefixPath,//dylib注入位置
        const char *c_removeDylibPath,//删除的dylib路径,多个用逗号分隔
        const char *c_appName,//app名称
        const char *c_appVersion,//app版本
        const char *c_appBundleId,//app包名
        const char *c_appIconPath,//app图标路径
        const char *c_outputPath,//输出路径
        int deletePlugIns,//删除插件
        int deleteWatchPlugIns,//删除手表插件
        int deleteDeviceSupport,//删除设备机型限制
        int deleteSchemeURL,//删除schemeURL应用跳转
        int enableFileAccess,//是否启用文件访问
        int sign,//是否签名
        int zipLevel,//压缩等级1~9
        int zipIpa,//是否压缩Payload
        int showLog,//是否显示日志
        char *error//错误信息
) {
    string ipaPath = c_ipaPath;
    string p12Path = c_p12Path;
    string p12Password = c_p12Password;
    string mpPath = c_mpPath;
    string removeDylibPath = c_removeDylibPath;//"@rpath/Lottie.framework/Lottie";
    string outputFile = GetAbsolutPath(c_outputPath);
    string dylibFilePath = c_dylibFilePath;
    string dylibPrefixPath = c_dylibPrefixPath;
    string iconPath = c_appIconPath;
    string appName = c_appName;
    string appVersion = c_appVersion;
    string appBundleId = c_appBundleId;

    ZTimer timer;
    if (outputFile.empty()) {
        if (showLog) {
            ZLog::ErrorV("output path is empty\n");
        }
        snprintf(error, 1024, "output path is empty");
        return;
    }

    if(!IsFileExists(ipaPath.c_str())){
        if (showLog) {
            ZLog::ErrorV("ipa file not exists: %s\n", ipaPath.c_str());
        }
        snprintf(error, 1024, "ipa file not exists: %s", ipaPath.c_str());
        return;
    }

    ZSignAsset zSignAsset;
    if (!zSignAsset.Init("", p12Path, mpPath, "", p12Password)) {
        snprintf(error, 1024, "init sign asset failed");
        return;
    }

    CreateFolder(outputFile.c_str());
//        if (showLog) {
//            ZLog::ErrorV("创建目录 %s 失败!", outputFile.c_str());
//        }
//        snprintf(error, 1024, "创建目录 %s 失败!", outputFile.c_str());
//        return;

    if (showLog) {
        ZLog::PrintV("签名ipa: %s \n", outputFile.c_str());
    }

    if (IsZipFile(ipaPath)) {
        if (showLog) {
            ZLog::PrintV("解压中:\t%s\n", ipaPath.c_str());
        }
//        if (!SystemExec("unzip -qq -n -d '%s' '%s'", outputFile.c_str(), ipaPath.c_str())) {
//            if (showLog) {
//                ZLog::ErrorV("解压失败: %s\n", ipaPath.c_str());
//            }
//            snprintf(error, 1024, "解压失败: %s", ipaPath.c_str());
          ZLog::ErrorV("不支持签名未解压文件: %s\n", ipaPath.c_str());
          return;
//        }
//        unzip(ipaPath, tmpFolderPath);
    }

    ZAppBundle bundle;

    if (!showLog) {
        bundle.DisableLog();
    }

    string value;
    SHASum(E_SHASUM_TYPE_1, "abc", value);

    bool bRet;
    try {
        bool force = true;
        bool weakInject = false;
        bool enableCache = false;

        bRet = bundle.SignFolder(
                &zSignAsset,
                outputFile,
                appBundleId,
                appVersion,
                appName,
                iconPath,
                dylibFilePath,
                dylibPrefixPath,
                removeDylibPath,
                deletePlugIns != 0,
                deleteWatchPlugIns != 0,
                deleteDeviceSupport != 0,
                deleteSchemeURL != 0,
                enableFileAccess != 0,
                sign != 0,
                force,
                weakInject,
                enableCache
        );
    } catch (string e) {
        snprintf(error, 1024, "%s", e.c_str());
        bRet = false;
    }
    if (bRet && zipIpa) {
        if (!outputFile.empty()) {
            timer.Reset();
            size_t pos = bundle.m_strAppFolder.rfind("/Payload");
            if (string::npos == pos) {
                ZLog::Error("找不到Payload目录!\n");
                return;
            }

            ZLog::PrintV("压缩中: \t%s ... \n", outputFile.c_str());
            string strBaseFolder = bundle.m_strAppFolder.substr(0, pos);
            char szOldFolder[PATH_MAX] = {0};
            if (nullptr != getcwd(szOldFolder, PATH_MAX)) {
                if (0 == chdir(strBaseFolder.c_str())) {
                    zipLevel = zipLevel > 9 ? 9 : zipLevel;
                    RemoveFile(outputFile.c_str());
//                    SystemExec("zip -q -%u -r '%s%s' Payload", zipLevel, outputFile.c_str(), ".tmp");
                    RemoveFolder(outputFile.c_str());
                    RenameFile((outputFile + ".tmp").c_str(), outputFile.c_str());
                    chdir(szOldFolder);
                    if (!IsFileExists(outputFile.c_str())) {
                        ZLog::Error("压缩失败!\n");
                        return;
                    }
                }
            }
            timer.PrintResult(true, "压缩成功! (%s)",
                              GetFileSizeString(outputFile.c_str()).c_str());
        } else {
            timer.PrintResult(true, "不压缩!");
        }
    }
//    if (tmpFolderDelete) {
//        RemoveFolder(tmpFolderPath.c_str());
//    }
    if (showLog) {
        if (sign) {
            timer.PrintResult(bRet, "签名 %s!", bRet ? "OK" : "Failed");
        } else {
            timer.PrintResult(bRet, "修改配置 %s!", bRet ? "OK" : "Failed");
        }
    }
}

int main() {
    string basePath = "/Users/lake/dounine/github/rust_cms_builder/cpp";
    //使用p12，需要打开openssl3兼容legacy_sect  链接：https://www.practicalnetworking.net/practical-tls/openssl-3-and-legacy-providers/
    string p12Path = basePath + "/data/iphone.p12";
    string mpPath = basePath + "/data/iphone.mobileprovision";
    string zipIpaPath = basePath + "/data/oCUSwHpsoPM/app.ipa";
    string ipaPath = basePath + "/data/app/Payload";
    string dylibFilePath = basePath + "/data/ios.dylib";
    string p12Password = "1";
    string iconPath = "";

    sign_ipa(
            ipaPath.c_str(),
            p12Path.c_str(),
            p12Password.c_str(),
            mpPath.c_str(),
            dylibFilePath.c_str(),//dylibFilePath.c_str(),
            "@executable_path/",
            "",
            "你好",
            "1.0",
            "com.lake.video",
            iconPath.c_str(),
            ipaPath.c_str(),
            false,
            false,
            false,
            false,
            false,
            true,
            3,
            false,
            true,
            nullptr);
//sleep 1
    sleep(1);
//    SystemExec("zip -q -r -3 %s %s", zipIpaPath.c_str(), ipaPath.c_str());
    return 0;
}