import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'IRFlow Timeline',
  description: 'High-performance DFIR timeline analysis tool for macOS',
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
    ['meta', { property: 'og:description', content: 'High-performance DFIR timeline analysis tool for macOS — search, visualize, and investigate 30GB+ forensic timelines' }],
    ['meta', { property: 'og:image', content: 'https://r3nzsec.github.io/irflow-timeline/IRFlow-Timeline-Github.png' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:url', content: 'https://r3nzsec.github.io/irflow-timeline/' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:title', content: 'IRFlow Timeline' }],
    ['meta', { name: 'twitter:description', content: 'High-performance DFIR timeline analysis tool for macOS — search, visualize, and investigate 30GB+ forensic timelines' }],
    ['meta', { name: 'twitter:image', content: 'https://r3nzsec.github.io/irflow-timeline/IRFlow-Timeline-Github.png' }],
    ['script', { 'data-goatcounter': 'https://irflowtimeline.goatcounter.com/count', async: '', src: '//gc.zgo.at/count.js' }]
  ],
  themeConfig: {
    logo: '/logo.png',
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Getting Started', link: '/getting-started/installation' },
      { text: 'Features', link: '/features/virtual-grid' },
      { text: 'Workflows', link: '/workflows/kape-integration' },
      { text: 'DFIR Tips', link: '/dfir-tips/ransomware-investigation' },
      { text: 'Reference', link: '/reference/keyboard-shortcuts' },
      { text: 'Author', link: '/about/author' },
      {
        text: 'v1.0.3-beta',
        items: [
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
            { text: 'Installation', link: '/getting-started/installation' },
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
            { text: 'Bookmarks & Tags', link: '/features/bookmarks-tags' },
            { text: 'Color Rules', link: '/features/color-rules' }
          ]
        },
        {
          text: 'Analytics',
          items: [
            { text: 'Histogram', link: '/features/histogram' },
            { text: 'Process Inspector', link: '/features/process-tree' },
            { text: 'Lateral Movement Tracker', link: '/features/lateral-movement' },
            { text: 'Persistence Analyzer', link: '/features/persistence-analyzer' },
            { text: 'Gap & Burst Analysis', link: '/features/gap-burst-analysis' },
            { text: 'IOC Matching', link: '/features/ioc-matching' },
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
            { text: 'Merging Timelines', link: '/workflows/merge-tabs' }
          ]
        }
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Keyboard Shortcuts', link: '/reference/keyboard-shortcuts' },
            { text: 'KAPE Profiles', link: '/reference/kape-profiles' },
            { text: 'Performance Tips', link: '/reference/performance-tips' },
            { text: 'FAQ & Troubleshooting', link: '/reference/faq' }
          ]
        }
      ],
      '/dfir-tips/': [
        {
          text: 'DFIR Tips & Tricks',
          items: [
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
      copyright: 'Copyright 2025 IRFlow Timeline'
    },
    editLink: {
      pattern: 'https://github.com/r3nzsec/irflow-timeline/edit/main/docs/:path',
      text: 'Edit this page on GitHub'
    }
  }
})
