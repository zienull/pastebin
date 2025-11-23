// ==UserScript==
// @name         Hexo Blog Encrypt Auto Decrypt (Direct & SPA Compatible)
// @namespace    http://tampermonkey.net/
// @version      1.2
// @description  直接执行 Hexo Blog Encrypt 的解密流程，并兼容同页跳转 (SPA)。
// @author       Gemini
// @match        https://zienull.github.io/*
// @match        https://xirka.us/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    // --- 全局配置 ---
    const DECRYPTION_CONFIGS = [
        // {
        //     regex: /^\/draft\/.+$/,
        //     password: 'draft_access_key'
        // },
        {
            // 匹配 /baka-diary/251029/ 这样的路径 (日期后带斜杠)
            regex: /^\/baka-diary\/\d+\/$/,
            password: '????'
        },
        {
            // 匹配 /diary-baka/251029/ 这样的路径 (日期后带斜杠)
            regex: /^\/diary-baka\/\d+\/$/,
            password: '????'
        }
        // 您可以添加更多配置...
    ];

    // --- 静态辅助函数 (与加密数据无关，保持在外部) ---

    const cryptoObj = window.crypto || window.msCrypto;
    const keySalt = textToArray("too young too simple");
    const ivSalt = textToArray("sometimes naive!");

    function hexToArray(s) {
        return new Uint8Array(
            s.match(/[\da-f]{2}/gi).map((h) => parseInt(h, 16)),
        );
    }

    function textToArray(s) {
        var i = s.length;
        var n = 0;
        var ba = [];
        for (var j = 0; j < i;) {
            var c = s.codePointAt(j);
            if (c < 128) {
                ba[n++] = c;
                j++;
            } else if (c > 127 && c < 2048) {
                ba[n++] = (c >> 6) | 192;
                ba[n++] = (c & 63) | 128;
                j++;
            } else if (c > 2047 && c < 65536) {
                ba[n++] = (c >> 12) | 224;
                ba[n++] = ((c >> 6) & 63) | 128;
                ba[n++] = (c & 63) | 128;
                j++;
            } else {
                ba[n++] = (c >> 18) | 240;
                ba[n++] = ((c >> 12) & 63) | 128;
                ba[n++] = ((c >> 6) & 63) | 128;
                ba[n++] = (c & 63) | 128;
                j += 2;
            }
        }
        return new Uint8Array(ba);
    }

    function getKeyMaterial(password) {
        let encoder = new TextEncoder();
        return cryptoObj.subtle.importKey(
            "raw",
            encoder.encode(password), {
                name: "PBKDF2",
            },
            false,
            ["deriveKey", "deriveBits"],
        );
    }

    function getHmacKey(keyMaterial) {
        return cryptoObj.subtle.deriveKey({
                name: "PBKDF2",
                hash: "SHA-256",
                salt: keySalt.buffer,
                iterations: 1024,
            },
            keyMaterial, {
                name: "HMAC",
                hash: "SHA-256",
                length: 256,
            },
            true,
            ["verify"],
        );
    }

    function getDecryptKey(keyMaterial) {
        return cryptoObj.subtle.deriveKey({
                name: "PBKDF2",
                hash: "SHA-256",
                salt: keySalt.buffer,
                iterations: 1024,
            },
            keyMaterial, {
                name: "AES-CBC",
                length: 256,
            },
            true,
            ["decrypt"],
        );
    }

    function getIv(keyMaterial) {
        return cryptoObj.subtle.deriveBits({
                name: "PBKDF2",
                hash: "SHA-256",
                salt: ivSalt.buffer,
                iterations: 512,
            },
            keyMaterial,
            16 * 8,
        );
    }

    async function getExecutableScript(oldElem) {
        let out = document.createElement("script");
        const attList = [
            "type", "text", "src", "crossorigin", "defer", "referrerpolicy",
        ];
        attList.forEach((att) => {
            if (oldElem[att]) out[att] = oldElem[att];
        });
        return out;
    }

    async function convertHTMLToElement(content) {
        let out = document.createElement("div");
        out.innerHTML = content;
        out.querySelectorAll("script").forEach(async (elem) => {
            elem.replaceWith(await getExecutableScript(elem));
        });
        return out;
    }

    // --- 健壮的元素等待函数 (保持不变) ---
    function waitForElement(selector, timeout = 5000) {
        return new Promise(resolve => {
            if (document.querySelector(selector)) {
                return resolve(document.querySelector(selector));
            }

            const observer = new MutationObserver((mutations, obs) => {
                if (document.querySelector(selector)) {
                    obs.disconnect();
                    resolve(document.querySelector(selector));
                }
            });

            observer.observe(document.body, { childList: true, subtree: true });

            setTimeout(() => {
                observer.disconnect();
                resolve(null);
            }, timeout);
        });
    }

    // --- 核心解密函数 (现在接受密码作为参数) ---

    /**
     * @param {string} password - 匹配到的密码
     */
    async function autoDecrypt(password) {
        console.log("启动 Hexo Blog Encrypt 自动解密，等待加密容器加载...");

        // 1. 等待主加密容器出现 (使用 MutationObserver)
        const container = await waitForElement("#hexo-blog-encrypt");

        if (!container) {
            console.warn("未找到加密容器 #hexo-blog-encrypt，停止解密。");
            return;
        }

        // 2. 获取本次解密所需的数据 (在元素加载后获取，以适应 SPA 刷新)
        const mainElement = container;
        const wrongPassMessage = mainElement.dataset["wpm"] || "Wrong password!";
        const wrongHashMessage = mainElement.dataset["whm"] || "Wrong content hash!";
        const dataElement = mainElement.getElementsByTagName("script")["hbeData"];

        if (!dataElement || !dataElement.innerText || !dataElement.dataset["hmacdigest"]) {
            console.warn("找到加密容器，但未找到 hbeData 脚本或数据，可能已解密或结构不匹配。");
            return;
        }

        const encryptedData = dataElement.innerText;
        const HmacDigist = dataElement.dataset["hmacdigest"];
        const knownPrefix = "<hbe-prefix></hbe-prefix>";

        console.log(`加密容器加载完毕，开始使用密码 '${password}' 进行解密...`);

        // 3. 定义依赖于本次数据的子函数 (verifyContent 和 decrypt)

        async function verifyContent(key, content) {
            const encoder = new TextEncoder();
            const encoded = encoder.encode(content);
            let signature = hexToArray(HmacDigist);

            const result = await cryptoObj.subtle.verify({
                    name: "HMAC",
                    hash: "SHA-256",
                },
                key,
                signature,
                encoded,
            );
            console.log(`Verification result: ${result}`);
            if (!result) {
                alert(wrongHashMessage);
                console.log(`${wrongHashMessage}, got `, signature, ` but proved wrong.`);
            }
            return result;
        }

        async function decryptCore(decryptKey, iv, hmacKey) {
            let typedArray = hexToArray(encryptedData);

            const result = await cryptoObj.subtle
                .decrypt({
                        name: "AES-CBC",
                        iv: iv,
                    },
                    decryptKey,
                    typedArray.buffer,
                )
                .then(async (result) => {
                    const decoder = new TextDecoder();
                    const decoded = decoder.decode(result);

                    if (!decoded.startsWith(knownPrefix)) {
                        throw "Decode successfully but not start with KnownPrefix.";
                    }

                    const hideButton = document.createElement("button");
                    hideButton.textContent = "Encrypt again";
                    hideButton.type = "button";
                    hideButton.classList.add("hbe-button");
                    // 移除 localStorage 逻辑

                    mainElement.style.display = "inline";
                    mainElement.innerHTML = "";
                    mainElement.appendChild(await convertHTMLToElement(decoded));
                    mainElement.appendChild(hideButton);

                    document.querySelectorAll("img").forEach((elem) => {
                        if (elem.getAttribute("data-src") && !elem.src) {
                            elem.src = elem.getAttribute("data-src");
                        }
                    });

                    var event = new Event("hexo-blog-decrypt");
                    window.dispatchEvent(event);

                    return await verifyContent(hmacKey, decoded);
                })
                .catch((e) => {
                    alert(wrongPassMessage);
                    console.error("解密或前缀校验失败:", e);
                    return false;
                });

            return result;
        }

        // 4. 执行解密逻辑
        try {
            const keyMaterial = await getKeyMaterial(password); // 使用传入的 password
            const hmacKey = await getHmacKey(keyMaterial);
            const decryptKey = await getDecryptKey(keyMaterial);
            const iv = await getIv(keyMaterial);

            const decrypted = await decryptCore(decryptKey, iv, hmacKey);

            if (decrypted) {
                console.log("内容已成功解密。");
                if (document.getElementsByClassName("article-prev").length == 0) {
                    // 1. 创建导航栏元素
                    const navElement = createNavElement(window.location.pathname);

                    // 2. 查找插入位置的父容器 (例如 #hexo-blog-encrypt 的父容器)
                    // 假设 #hexo-blog-encrypt 位于 article-content-container 内部
                    const contentContainer = mainElement.parentElement;

                    // 3. 找到注释容器（或文章结尾的可靠位置）进行插入
                    const commentContainer = document.getElementById('comment-container');

                    if (navElement && contentContainer) {
                        if (commentContainer) {
                            // 如果有评论容器，插在评论容器之前
                            contentContainer.insertBefore(navElement, commentContainer);
                            console.log("导航栏已插入到评论容器之前。");
                        } else {
                            // 否则，插在 #hexo-blog-encrypt (mainElement) 的后面
                            mainElement.after(navElement);
                            console.log("导航栏已插入到解密内容之后。");
                        }
                    }
                }
            } else {
                console.log("解密失败（可能是密码错误或内容哈希不匹配）。");
            }
        } catch (error) {
            console.error("解密过程中发生致命错误:", error);
            alert("自动解密失败，请检查控制台。");
        }
    }

    /**
 * 插入前一篇/后一篇的导航按钮，通过修改 URL 中的日期。
 * * @param {string} currentPath 当前页面的路径，例如 '/baka-diary/251029/'
 * @returns {HTMLElement} 包含导航链接的 HTML 元素，或者 null（如果路径不匹配）。
 */
    function createNavElement(currentPath) {
        // 1. 尝试从路径中提取日期
        const dateMatch = currentPath.match(/\/(\d{6,8})\/$/);
        if (!dateMatch) {
            console.warn("未在路径中找到日期格式 (\\/YYYYMMDD\\/)，无法创建导航。");
            return null;
        }

        // 提取的日期字符串 (e.g., '251029')
        const dateStr = dateMatch[1];
        const datePrefix = currentPath.substring(0, dateMatch.index + 1); // e.g., '/baka-diary/'

        // 为了进行日期加减运算，我们将其标准化为 Date 对象
        // 假设日期格式是 YYYYMMDD 或 YYMMDD
        let year, month, day;
        if (dateStr.length === 8) {
            year = parseInt(dateStr.substring(0, 4), 10);
            month = parseInt(dateStr.substring(4, 6), 10);
            day = parseInt(dateStr.substring(6, 8), 10);
        } else if (dateStr.length === 6) {
            // 假设是 YYMMDD，添加 20xx
            year = parseInt('20' + dateStr.substring(0, 2), 10);
            month = parseInt(dateStr.substring(2, 4), 10);
            day = parseInt(dateStr.substring(4, 6), 10);
        } else {
            return null;
        }

        // JS 的月份是从 0 开始的，所以需要减 1
        const currentDate = new Date(year, month - 1, day);

        // 2. 计算前一天和后一天的日期

        const prevDate = new Date(currentDate);
        prevDate.setDate(currentDate.getDate() - 1);

        const nextDate = new Date(currentDate);
        nextDate.setDate(currentDate.getDate() + 1);

        /** 将 Date 对象格式化回 YYYYMMDD 或 YYMMDD 字符串 */
        function formatDate(date) {
            const y = date.getFullYear().toString();
            const m = (date.getMonth() + 1).toString().padStart(2, '0');
            const d = date.getDate().toString().padStart(2, '0');

            // 保持与原始 URL 长度一致 (6位或8位)
            if (dateStr.length === 8) {
                return `${y}${m}${d}`;
            } else { // 6位格式
                return `${y.substring(2)}${m}${d}`;
            }
        }

        const prevDateStr = formatDate(prevDate);
        const nextDateStr = formatDate(nextDate);

        // 3. 生成新的 URL
        const prevUrl = `${datePrefix}${prevDateStr}/`;
        const nextUrl = `${datePrefix}${nextDateStr}/`;

        // 4. 创建和填充导航 HTML 结构
        const navElement = document.createElement('div');
        navElement.className = "article-nav my-8 flex justify-between items-center px-2 sm:px-6 md:px-8";
        navElement.innerHTML = `
        <div class="article-prev border-border-color shadow-redefine-flat shadow-shadow-color-2 rounded-medium px-4 py-2 hover:shadow-redefine-flat-hover hover:shadow-shadow-color-2">
            <a class="prev" rel="prev" href="${prevUrl}">
                <span class="left arrow-icon flex justify-center items-center">
                    <i class="fa-solid fa-chevron-left"></i>
                </span>
                <span class="title flex justify-center items-center">
                    <span class="post-nav-title-item truncate max-w-48">上一篇</span>
                    <span class="post-nav-item">上一篇</span>
                </span>
            </a>
        </div>

        <div class="article-next border-border-color shadow-redefine-flat shadow-shadow-color-2 rounded-medium px-4 py-2 hover:shadow-redefine-flat-hover hover:shadow-shadow-color-2">
            <a class="next" rel="next" href="${nextUrl}">
                <span class="title flex justify-center items-center">
                    <span class="post-nav-title-item truncate max-w-48">下一篇</span>
                    <span class="post-nav-item">下一篇</span>
                </span>
                <span class="right arrow-icon flex justify-center items-center">
                    <i class="fa-solid fa-chevron-right"></i>
                </span>
            </a>
        </div>
    `;

        return navElement;
    }

    // --- 路径匹配和 SPA 监听逻辑 ---

    const contentContainer = document.querySelector('.main-container, .post-container, #content, body');
    // ^^^ 请根据您主题的文章内容父容器选择最合适的 CSS Selector

    /** 检查当前路径是否需要解密，并返回对应的密码 */
    function getPasswordForCurrentPath() {
        let currentPath = window.location.pathname;
        for (const config of DECRYPTION_CONFIGS) {
            if (config.regex.test(currentPath)) {
                return config.password;
            }
        }
        return null;
    }

    /** 检查是否需要运行解密，并执行 */
    function runDecryptionIfApplicable() {
        const password = getPasswordForCurrentPath();

        if (password === null) {
            console.log(`当前路径 ${window.location.pathname} 不匹配任何自动解密配置。`);
            return;
        }

        // 只有当密码匹配时才调用 autoDecrypt
        // 这里的调用会触发 waitForElement 内部的 MutationObserver
        // 确保加密内容加载后再开始解密。
        autoDecrypt(password);
    }

    // 首次加载时运行
    runDecryptionIfApplicable();

    // --- 监听同页跳转 (SPA) ---
    if (contentContainer) {
        const observer = new MutationObserver((mutations, obs) => {
            // 简单地检查内容容器中的子元素是否被替换或更新
            // 如果 contentContainer 是页面的主要动态区域，这个监听就足够了

            // 重新连接观察器，因为 Hexo SPA 可能会替换整个内容容器
            // obs.disconnect(); // 在某些主题中，这里可能不需要断开/重连

            // 延迟一点时间，确保新的加密内容容器已经被主题脚本注入 DOM
            setTimeout(() => {
                runDecryptionIfApplicable();
            }, 1000); // 500ms 延迟通常足够让 SPA 脚本完成内容注入

        });

        // 监听子节点的添加或删除，以及它们的属性变化
        observer.observe(contentContainer, {
            childList: true,
            subtree: true
        });

        console.log(`SPA监听器已启动，目标容器: ${contentContainer.tagName}`);
    } else {
        console.warn("未找到内容父容器，SPA跳转可能无法自动解密。");
    }

})();