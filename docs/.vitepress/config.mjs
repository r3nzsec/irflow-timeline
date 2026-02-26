import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'IRFlow Timeline',
  description: 'High-performance DFIR timeline analysis tool for macOS',
  base: '/irflow-timeline/',
  head: [
    ['link', { rel: 'icon', href: '/irflow-timeline/favicon.ico' }]
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
        text: 'v2.1.2',
        items: [
          { text: 'Changelog', link: '/about/changelog' },
          { text: 'Credits', link: '/about/credits' }
        ]
      }
    ],
    sidebar: {
      '/getting-started/': [
        {
          text: 'Getting Started',
          items: [
            { text: 'Installation', link: '/getting-started/installation' },
            { text: 'Quick Start', link: '/getting-started/quick-start' },
            { text: 'Supported Formats', link: '/getting-started/supported-formats' }
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
            { text: 'Process Tree', link: '/features/process-tree' },
            { text: 'Lateral Movement', link: '/features/lateral-movement' },
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
            { text: 'Performance Tips', link: '/reference/performance-tips' }
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
            { text: 'Architecture', link: '/about/architecture' },
            { text: 'Changelog', link: '/about/changelog' },
            { text: 'Credits', link: '/about/credits' }
          ]
        }
      ]
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/r3nzsec/irflow-timeline' }
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
