import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'IRFlow Timeline',
  description: 'Native macOS DFIR timeline analysis with expanded AI application forensics for Grok Build, Claude, Codex, ChatGPT, Copilot, Gemini, Cursor, and more',
  base: '/irflow-timeline/',
  lastUpdated: true,
  cleanUrls: true,
  markdown: {
    image: {
      lazyLoading: true
    }
  },
  sitemap: {
    hostname: 'https://r3nzsec.github.io/irflow-timeline/'
  },
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/irflow-timeline/logo.svg' }],
    ['meta', { property: 'og:title', content: 'IRFlow Timeline' }],
    ['meta', { property: 'og:description', content: 'IRFlow Timeline 1.0.12 adds Diff Tabs — compare any two imported files into an Added / Removed / Changed timeline with field-level before/after — and fixes a tag and bookmark layer that was silently discarding annotations.' }],
    ['meta', { property: 'og:image', content: 'https://r3nzsec.github.io/irflow-timeline/IRFlow-Timeline-Home.png' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:url', content: 'https://r3nzsec.github.io/irflow-timeline/' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:title', content: 'IRFlow Timeline' }],
    ['meta', { name: 'twitter:description', content: 'IRFlow Timeline 1.0.12 adds Diff Tabs — compare any two imported files into an Added / Removed / Changed timeline with field-level before/after — and fixes a tag and bookmark layer that was silently discarding annotations.' }],
    ['meta', { name: 'twitter:image', content: 'https://r3nzsec.github.io/irflow-timeline/IRFlow-Timeline-Home.png' }],
    ['script', { 'data-goatcounter': 'https://irflowtimeline.goatcounter.com/count', async: '', src: '//gc.zgo.at/count.js' }],
    ['script', { type: 'application/ld+json' }, JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'SoftwareApplication',
      name: 'IRFlow Timeline',
      description: 'Native macOS DFIR timeline analysis with local AI application forensics for Grok Build, Claude, Codex, ChatGPT, Copilot, Gemini, Cursor, and other assistants.',
      softwareVersion: '1.0.12',
      operatingSystem: 'macOS',
      applicationCategory: 'SecurityApplication',
      url: 'https://r3nzsec.github.io/irflow-timeline/',
      downloadUrl: 'https://github.com/r3nzsec/irflow-timeline/releases/tag/v1.0.12',
      author: {
        '@type': 'Person',
        name: 'Renzon Cruz',
        url: 'https://x.com/r3nzsec'
      },
      offers: {
        '@type': 'Offer',
        price: '0',
        priceCurrency: 'USD'
      }
    })]
  ],
  outline: { level: 'deep' },
  themeConfig: {
    logo: '/logo.svg',
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Getting Started', link: '/getting-started/installation' },
      { text: 'Features', link: '/features/virtual-grid' },
      { text: 'Workflows', link: '/workflows/kape-integration' },
      { text: 'DFIR Tips', link: '/dfir-tips/ransomware-investigation' },
      { text: 'Blog', link: '/blog/' },
      { text: 'Reference', link: '/reference/keyboard-shortcuts' },
      { text: 'Author', link: '/about/author' },
      {
        text: 'v1.0.12',
        items: [
          { text: 'What’s New in v1.0.12', link: '/blog/v1.0.12-diff-tabs-and-triage' },
          { text: 'What’s New in v1.0.11', link: '/blog/v1.0.11-computer-history-verified' },
          { text: 'What’s New in v1.0.10', link: '/blog/v1.0.10-computer-history' },
          { text: 'Changelog', link: '/about/changelog' },
          { text: 'Roadmap', link: '/about/roadmap' },
          { text: 'Credits', link: '/about/credits' }
        ]
      },
      { text: 'Download', link: 'https://github.com/r3nzsec/irflow-timeline/releases' }
    ],
    sidebar: {
      '/getting-started/': [
        {
          text: 'Getting Started',
          items: [
            { text: 'Interactive Demo', link: '/getting-started/demo' },
            { text: 'Installation', link: '/getting-started/installation' },
            { text: 'Auto-Update', link: '/getting-started/auto-update' },
            { text: 'Quick Start', link: '/getting-started/quick-start' },
            { text: 'Supported Formats', link: '/getting-started/supported-formats' },
            { text: 'Architecture', link: '/getting-started/architecture' }
          ]
        }
      ],
      '/features/': [
        {
          text: 'Core',
          items: [
            { text: 'Virtual Grid', link: '/features/virtual-grid' },
            { text: 'Search & Filtering', link: '/features/search-filtering' },
            { text: 'Filter Presets', link: '/features/filter-presets' },
            { text: 'Bookmarks & Tags', link: '/features/bookmarks-tags' },
            { text: 'Color Rules', link: '/features/color-rules' }
          ]
        },
        {
          text: 'Analytics',
          items: [
            { text: 'Histogram', link: '/features/histogram' },
            { text: 'Sigma Detection', link: '/features/sigma-detection' },
            { text: 'AI Artifacts', link: '/features/ai-artifacts' },
            { text: 'Process Inspector', link: '/features/process-tree' },
            { text: 'Analyst Profiles', link: '/features/analyst-profiles' },
            { text: 'Lateral Movement Tracker', link: '/features/lateral-movement' },
            { text: 'RDP Bitmap Cache', link: '/features/rdp-bitmap-cache' },
            { text: 'Persistence Analyzer', link: '/features/persistence-analyzer' },
            { text: 'Gap & Burst Analysis', link: '/features/gap-burst-analysis' },
            { text: 'IOC Matching', link: '/features/ioc-matching' },
            { text: 'VirusTotal Integration', link: '/features/virustotal' },
            { text: 'NTFS Analysis', link: '/features/ntfs-analysis' },
            { text: 'Stacking', link: '/features/stacking' },
            { text: 'Log Source Coverage', link: '/features/log-source-coverage' }
          ]
        }
      ],
      '/workflows/': [
        {
          text: 'Workflows',
          items: [
            { text: 'KAPE Integration', link: '/workflows/kape-integration' },
            { text: 'Sessions', link: '/workflows/sessions' },
            { text: 'Export & Reports', link: '/workflows/export-reports' },
            { text: 'Multi-Tab Analysis', link: '/workflows/multi-tab' },
            { text: 'Merging Timelines', link: '/workflows/merge-tabs' },
            { text: 'Diff Tabs', link: '/workflows/diff-tabs' }
          ]
        }
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Keyboard Shortcuts', link: '/reference/keyboard-shortcuts' },
            { text: 'KAPE Profiles', link: '/reference/kape-profiles' },
            { text: 'Preferences', link: '/reference/preferences' },
            { text: 'Performance Tips', link: '/reference/performance-tips' },
            { text: 'FAQ & Troubleshooting', link: '/reference/faq' }
          ]
        }
      ],
      '/dfir-tips/': [
        {
          text: 'DFIR Tips & Tricks',
          items: [
            {
              text: 'AI Query History',
              collapsed: false,
              items: [
                { text: 'Overview', link: '/dfir-tips/ai-query-history' },
                { text: 'Claude Desktop', link: '/dfir-tips/ai-apps/claude-desktop' },
                { text: 'ChatGPT / Codex', link: '/dfir-tips/ai-apps/chatgpt-codex' },
                { text: 'Grok AI', link: '/dfir-tips/ai-apps/grok-ai' },
                { text: 'Cursor', link: '/dfir-tips/ai-apps/cursor' },
                { text: 'Gemini', link: '/dfir-tips/ai-apps/gemini' }
              ]
            },
            { text: 'Ransomware Investigation', link: '/dfir-tips/ransomware-investigation' },
            { text: 'Lateral Movement Tracing', link: '/dfir-tips/lateral-movement-tracing' },
            { text: 'Malware Execution Analysis', link: '/dfir-tips/malware-execution-analysis' },
            { text: 'Brute Force & Account Compromise', link: '/dfir-tips/brute-force-account-compromise' },
            { text: 'Insider Threat & Exfiltration', link: '/dfir-tips/insider-threat-exfiltration' },
            { text: 'Log Tampering Detection', link: '/dfir-tips/log-tampering-detection' },
            { text: 'Persistence Hunting', link: '/dfir-tips/persistence-hunting' },
            { text: 'KAPE Triage Workflow', link: '/dfir-tips/kape-triage-workflow' },
            { text: 'Threat Intel IOC Sweeps', link: '/dfir-tips/threat-intel-ioc-sweeps' },
            { text: 'Building the Final Report', link: '/dfir-tips/building-final-report' }
          ]
        }
      ],
      '/blog/': [
        {
          text: 'IRFlow Timeline Blog',
          items: [
            { text: 'All Posts', link: '/blog/' },
            { text: 'v1.0.12 — Diff Tabs & Triage', link: '/blog/v1.0.12-diff-tabs-and-triage' },
            { text: 'v1.0.11 — Computer History Verified', link: '/blog/v1.0.11-computer-history-verified' },
            { text: 'v1.0.10 — ChatGPT Computer History', link: '/blog/v1.0.10-computer-history' },
            { text: 'v1.0.9 — Large EVTX Reliability', link: '/blog/v1.0.9-large-evtx-imports' },
            { text: 'v1.0.8 — AI Application Forensics', link: '/blog/v1.0.8-ai-application-forensics' }
          ]
        }
      ],
      '/about/': [
        {
          text: 'About',
          items: [
            { text: 'Author', link: '/about/author' },
            { text: 'Changelog', link: '/about/changelog' },
            { text: 'Roadmap', link: '/about/roadmap' },
            { text: 'Credits', link: '/about/credits' }
          ]
        }
      ]
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/r3nzsec/irflow-timeline' },
      { icon: 'x', link: 'https://x.com/r3nzsec' },
      { icon: 'linkedin', link: 'https://www.linkedin.com/in/renzoncruz/' }
    ],
    search: {
      provider: 'local'
    },
    footer: {
      message: 'Built for the DFIR community.',
      copyright: 'Copyright 2025-2026 IRFlow Timeline'
    },
    editLink: {
      pattern: 'https://github.com/r3nzsec/irflow-timeline/edit/main/docs/:path',
      text: 'Edit this page on GitHub'
    },
    externalLinkIcon: true,
    returnToTopLabel: 'Back to top',
    docFooter: {
      prev: 'Previous',
      next: 'Next'
    }
  }
})
