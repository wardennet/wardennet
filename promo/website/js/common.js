// WardenNet - 通用交互脚本
(function() {
  'use strict';

  // ========== 移动端菜单 ==========
  function initMobileMenu() {
    var toggle = document.querySelector('.navbar-toggle');
    var links = document.querySelector('.navbar-links');
    if (!toggle || !links) return;
    toggle.addEventListener('click', function() {
      links.classList.toggle('open');
    });
    // 点击链接后关闭菜单
    links.querySelectorAll('a').forEach(function(link) {
      link.addEventListener('click', function() {
        links.classList.remove('open');
      });
    });
  }

  // ========== 导航栏滚动效果 ==========
  function initNavbarScroll() {
    var navbar = document.querySelector('.navbar');
    if (!navbar) return;
    var lastScroll = 0;
    window.addEventListener('scroll', function() {
      var currentScroll = window.pageYOffset;
      if (currentScroll > 100) {
        navbar.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.3)';
      } else {
        navbar.style.boxShadow = 'none';
      }
      lastScroll = currentScroll;
    });
  }

  // ========== FAQ 折叠 ==========
  function initFaq() {
    var questions = document.querySelectorAll('.faq-question');
    questions.forEach(function(q) {
      q.addEventListener('click', function() {
        var item = q.parentElement;
        var wasOpen = item.classList.contains('open');
        // 关闭所有
        document.querySelectorAll('.faq-item').forEach(function(i) {
          i.classList.remove('open');
        });
        // 打开当前（如果之前关闭）
        if (!wasOpen) {
          item.classList.add('open');
        }
      });
    });
  }

  // ========== 代码高亮（简单版本） ==========
  function initCodeHighlight() {
    var codeBlocks = document.querySelectorAll('.code-block code');
    codeBlocks.forEach(function(code) {
      var text = code.textContent;
      // 注释
      text = text.replace(/\/\/[^\n]*/g, '<span class="comment">$&</span>');
      text = text.replace(/#[^\n]*/g, '<span class="comment">$&</span>');
      text = text.replace(/\/\*[\s\S]*?\*\//g, '<span class="comment">$&</span>');
      // 字符串
      text = text.replace(/"[^"]*"/g, '<span class="string">$&</span>');
      text = text.replace(/'[^']*'/g, '<span class="string">$&</span>');
      // 数字
      text = text.replace(/\b\d+\.?\d*\b/g, '<span class="number">$&</span>');
      // 关键字
      var keywords = ['function', 'var', 'let', 'const', 'return', 'if', 'else', 'for', 'while', 'class', 'new', 'async', 'await', 'import', 'export', 'from', 'package', 'func', 'main', 'command', 'config', 'detector', 'cloud', 'ipset', 'rule', 'type', 'true', 'false', 'nil', 'null'];
      var kwRegex = new RegExp('\\b(' + keywords.join('|') + ')\\b', 'g');
      text = text.replace(kwRegex, '<span class="keyword">$1</span>');
      code.innerHTML = text;
    });
  }

  // ========== 文档侧边栏滚动高亮 ==========
  function initDocSidebar() {
    var sidebar = document.querySelector('.doc-sidebar');
    if (!sidebar) return;
    var links = sidebar.querySelectorAll('.doc-nav a');
    var content = document.querySelector('.doc-content');
    if (!content || links.length === 0) return;

    // 给 h2/h3 添加 id（如果没有）
    content.querySelectorAll('h2, h3').forEach(function(heading) {
      if (!heading.id) {
        heading.id = heading.textContent.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^\w\u4e00-\u9fa5-]/g, '');
      }
    });
  }

  // ========== 平滑滚动锚点 ==========
  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
      anchor.addEventListener('click', function(e) {
        var href = this.getAttribute('href');
        if (href === '#') return;
        var target = document.querySelector(href);
        if (target) {
          e.preventDefault();
          var offset = 80; // 导航栏高度
          var top = target.offsetTop - offset;
          window.scrollTo({ top: top, behavior: 'smooth' });
        }
      });
    });
  }

  // ========== 当前导航高亮 ==========
  function initActiveNav() {
    var path = window.location.pathname;
    var links = document.querySelectorAll('.navbar-links a');
    links.forEach(function(link) {
      var href = link.getAttribute('href');
      if (href === path || (href === 'index.html' && (path === '/' || path.endsWith('/')))) {
        link.classList.add('active');
      }
      // 文档中心子页面高亮文档链接
      if (path.includes('/docs/') && href === 'docs/index.html') {
        link.classList.add('active');
      }
    });
  }

  // ========== 初始化 ==========
  document.addEventListener('DOMContentLoaded', function() {
    initMobileMenu();
    initNavbarScroll();
    initFaq();
    // initCodeHighlight();  // 已注释：避免重复 span 包裹破坏 HTML
    initDocSidebar();
    initSmoothScroll();
    initActiveNav();
  });
})();
