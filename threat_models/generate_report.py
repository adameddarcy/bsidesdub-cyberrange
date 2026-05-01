#!/usr/bin/env python3
"""
Generate a modern, interactive HTML threat model report.
"""

import json
import subprocess
import sys
from datetime import datetime
from html import escape

def run_pytm_json():
    """Run the threat model and capture JSON output."""
    result = subprocess.run(
        [sys.executable, "cyber_range_tm.py", "--json", "/dev/stdout"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"Error running threat model: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)

def get_severity_color(severity):
    """Return color classes for severity levels."""
    colors = {
        "Very High": ("bg-red-600", "text-red-600", "border-red-600"),
        "High": ("bg-orange-500", "text-orange-500", "border-orange-500"),
        "Medium": ("bg-yellow-500", "text-yellow-500", "border-yellow-500"),
        "Low": ("bg-blue-500", "text-blue-500", "border-blue-500"),
        "Very Low": ("bg-gray-400", "text-gray-400", "border-gray-400"),
    }
    return colors.get(severity, ("bg-gray-500", "text-gray-500", "border-gray-500"))

def get_severity_order(severity):
    """Return sort order for severity."""
    order = {"Very High": 0, "High": 1, "Medium": 2, "Low": 3, "Very Low": 4}
    return order.get(severity, 5)

def escape_for_script(obj):
    """Escape </script> tags in JSON data to prevent HTML parsing issues."""
    json_str = json.dumps(obj)
    return json_str.replace('</script>', '<\\/script>').replace('</Script>', '<\\/Script>').replace('</SCRIPT>', '<\\/SCRIPT>')

def generate_html(data):
    """Generate the HTML report."""
    
    findings = data.get("findings", [])
    elements = data.get("elements", [])
    dataflows = data.get("flows", [])
    
    findings_sorted = sorted(findings, key=lambda x: get_severity_order(x.get("severity", "Low")))
    
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    target_counts = {}
    for f in findings:
        target = f.get("target", "Unknown")
        target_counts[target] = target_counts.get(target, 0) + 1
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Range Threat Model Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.14.3/dist/cdn.min.js"></script>
    <style>
        [x-cloak] {{ display: none !important; }}
        .gradient-bg {{
            background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
        }}
        .card-hover {{
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .card-hover:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 40px rgba(0,0,0,0.15);
        }}
        .severity-badge {{
            font-size: 0.7rem;
            padding: 0.25rem 0.5rem;
            border-radius: 9999px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
    </style>
</head>
<body class="bg-slate-50 min-h-screen" x-data="threatModel()">
    
    <!-- Header -->
    <header class="gradient-bg text-white py-12 px-6">
        <div class="max-w-7xl mx-auto">
            <h1 class="text-4xl font-bold mb-2">Cyber Range Threat Model</h1>
            <p class="text-slate-300 text-lg">Three-tier cyber range environment for threat modelling workshops</p>
            <p class="text-slate-400 text-sm mt-4">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </header>

    <!-- Stats Bar -->
    <div class="bg-white border-b shadow-sm sticky top-0 z-10">
        <div class="max-w-7xl mx-auto px-6 py-4">
            <div class="flex flex-wrap gap-6 items-center justify-between">
                <div class="flex gap-6">
                    <div class="text-center">
                        <div class="text-3xl font-bold text-slate-800">{len(findings)}</div>
                        <div class="text-xs text-slate-500 uppercase tracking-wide">Total Findings</div>
                    </div>
                    <div class="text-center">
                        <div class="text-3xl font-bold text-red-600">{severity_counts.get("Very High", 0) + severity_counts.get("High", 0)}</div>
                        <div class="text-xs text-slate-500 uppercase tracking-wide">Critical/High</div>
                    </div>
                    <div class="text-center">
                        <div class="text-3xl font-bold text-slate-800">{len(elements)}</div>
                        <div class="text-xs text-slate-500 uppercase tracking-wide">Assets</div>
                    </div>
                    <div class="text-center">
                        <div class="text-3xl font-bold text-slate-800">{len(dataflows)}</div>
                        <div class="text-xs text-slate-500 uppercase tracking-wide">Data Flows</div>
                    </div>
                </div>
                
                <!-- Filters -->
                <div class="flex gap-3 items-center">
                    <input 
                        type="text" 
                        x-model="search" 
                        placeholder="Search findings..." 
                        class="px-4 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                    <select 
                        x-model="severityFilter" 
                        class="px-4 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                        <option value="">All Severities</option>
                        <option value="Very High">Very High</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                    </select>
                </div>
            </div>
        </div>
    </div>

    <main class="max-w-7xl mx-auto px-6 py-8">
        
        <!-- Navigation Tabs -->
        <div class="flex gap-2 mb-8 border-b border-slate-200">
            <button 
                @click="activeTab = 'findings'" 
                :class="activeTab === 'findings' ? 'border-blue-500 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'"
                class="px-4 py-3 font-medium border-b-2 transition-colors"
            >
                Findings
            </button>
            <button 
                @click="activeTab = 'assets'" 
                :class="activeTab === 'assets' ? 'border-blue-500 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'"
                class="px-4 py-3 font-medium border-b-2 transition-colors"
            >
                Assets
            </button>
            <button 
                @click="activeTab = 'dataflows'" 
                :class="activeTab === 'dataflows' ? 'border-blue-500 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'"
                class="px-4 py-3 font-medium border-b-2 transition-colors"
            >
                Data Flows
            </button>
            <button 
                @click="activeTab = 'diagram'" 
                :class="activeTab === 'diagram' ? 'border-blue-500 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'"
                class="px-4 py-3 font-medium border-b-2 transition-colors"
            >
                Diagram
            </button>
        </div>

        <!-- Findings Tab -->
        <div x-show="activeTab === 'findings'">
            <p class="text-sm text-slate-500 mb-4">Showing <span x-text="filteredFindings.length"></span> of <span x-text="findings.length"></span> findings</p>
            <div class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-slate-50 border-b border-slate-200">
                            <tr>
                                <th class="text-left px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide w-28">Severity</th>
                                <th class="text-left px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide w-24">ID</th>
                                <th class="text-left px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide">Description</th>
                                <th class="text-left px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide w-40">Target</th>
                                <th class="text-left px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide w-16">Details</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-100">
                            <template x-for="finding in filteredFindings" :key="finding.id">
                                <tr class="hover:bg-slate-50">
                                    <td class="px-4 py-3">
                                        <span 
                                            class="severity-badge text-white"
                                            :class="getSeverityBg(finding.severity)"
                                            x-text="finding.severity"
                                        ></span>
                                    </td>
                                    <td class="px-4 py-3 text-xs font-mono text-slate-500" x-text="finding.threat_id || finding.SID"></td>
                                    <td class="px-4 py-3 text-sm text-slate-800" x-text="finding.description"></td>
                                    <td class="px-4 py-3 text-sm font-medium text-slate-700" x-text="finding.target"></td>
                                    <td class="px-4 py-3">
                                        <button 
                                            @click="selectedFinding = finding; showModal = true"
                                            class="text-blue-500 hover:text-blue-700 text-sm font-medium"
                                        >
                                            View
                                        </button>
                                    </td>
                                </tr>
                            </template>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div x-show="filteredFindings.length === 0" class="text-center py-12 text-slate-500">
                No findings match your filters.
            </div>
        </div>
        
        <!-- Finding Detail Modal -->
        <div 
            x-show="showModal" 
            x-cloak
            class="fixed inset-0 z-50 overflow-y-auto"
            @keydown.escape.window="showModal = false"
        >
            <div class="flex items-center justify-center min-h-screen px-4 pt-4 pb-20">
                <div 
                    class="fixed inset-0 bg-slate-900/50 transition-opacity"
                    @click="showModal = false"
                ></div>
                
                <div class="relative bg-white rounded-xl shadow-2xl max-w-2xl w-full p-6 z-10">
                    <button 
                        @click="showModal = false"
                        class="absolute top-4 right-4 text-slate-400 hover:text-slate-600"
                    >
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                    
                    <template x-if="selectedFinding">
                        <div>
                            <div class="flex items-center gap-3 mb-4">
                                <span 
                                    class="severity-badge text-white"
                                    :class="getSeverityBg(selectedFinding.severity)"
                                    x-text="selectedFinding.severity"
                                ></span>
                                <span class="text-sm font-mono text-slate-400" x-text="selectedFinding.threat_id || selectedFinding.SID"></span>
                            </div>
                            
                            <h2 class="text-xl font-bold text-slate-800 mb-2" x-text="selectedFinding.description"></h2>
                            <p class="text-slate-600 mb-6">Target: <span class="font-semibold" x-text="selectedFinding.target"></span></p>
                            
                            <div class="space-y-4">
                                <div x-show="selectedFinding.details">
                                    <h4 class="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">Details</h4>
                                    <p class="text-sm text-slate-700" x-text="selectedFinding.details"></p>
                                </div>
                                <div x-show="selectedFinding.mitigations">
                                    <h4 class="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">Mitigations</h4>
                                    <p class="text-sm text-slate-700" x-text="selectedFinding.mitigations"></p>
                                </div>
                                <div x-show="selectedFinding.prerequisites">
                                    <h4 class="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">Prerequisites</h4>
                                    <p class="text-sm text-slate-700" x-text="selectedFinding.prerequisites"></p>
                                </div>
                                <div x-show="selectedFinding.references">
                                    <h4 class="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">References</h4>
                                    <p class="text-sm text-slate-700 break-all" x-text="selectedFinding.references"></p>
                                </div>
                            </div>
                        </div>
                    </template>
                </div>
            </div>
        </div>

        <!-- Assets Tab -->
        <div x-show="activeTab === 'assets'" x-cloak>
            <div class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
                <table class="w-full">
                    <thead class="bg-slate-50 border-b border-slate-200">
                        <tr>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">Name</th>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">Type</th>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">Boundary</th>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">Findings</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-100">
                        <template x-for="element in elements" :key="element.name">
                            <tr class="hover:bg-slate-50">
                                <td class="px-6 py-4 font-medium text-slate-800" x-text="element.name"></td>
                                <td class="px-6 py-4 text-sm text-slate-600" x-text="element.type"></td>
                                <td class="px-6 py-4 text-sm text-slate-600" x-text="element.inBoundary || '-'"></td>
                                <td class="px-6 py-4">
                                    <span 
                                        class="inline-flex items-center justify-center w-8 h-8 rounded-full text-sm font-semibold"
                                        :class="getElementFindingCount(element.name) > 0 ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500'"
                                        x-text="getElementFindingCount(element.name)"
                                    ></span>
                                </td>
                            </tr>
                        </template>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Data Flows Tab -->
        <div x-show="activeTab === 'dataflows'" x-cloak>
            <p class="text-sm text-slate-500 mb-4">Showing <span x-text="dataflows.length"></span> data flows</p>
            <div class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
                <table class="w-full">
                    <thead class="bg-slate-50 border-b border-slate-200">
                        <tr>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">Flow</th>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">From</th>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">To</th>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">Protocol</th>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">Port</th>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">Encrypted</th>
                            <th class="text-left px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wide">Findings</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-100">
                        <template x-for="flow in dataflows" :key="flow.name + flow.source + flow.sink">
                            <tr class="hover:bg-slate-50">
                                <td class="px-6 py-4 font-medium text-slate-800" x-text="flow.name"></td>
                                <td class="px-6 py-4 text-sm text-slate-600" x-text="flow.source"></td>
                                <td class="px-6 py-4 text-sm text-slate-600" x-text="flow.sink"></td>
                                <td class="px-6 py-4">
                                    <span class="px-2 py-1 bg-slate-100 rounded text-xs font-mono" x-text="flow.protocol || '-'"></span>
                                </td>
                                <td class="px-6 py-4 text-sm text-slate-600" x-text="flow.dstPort > 0 ? flow.dstPort : '-'"></td>
                                <td class="px-6 py-4">
                                    <span 
                                        class="px-2 py-1 rounded text-xs font-medium"
                                        :class="flow.isEncrypted ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'"
                                        x-text="flow.isEncrypted ? 'Yes' : 'No'"
                                    ></span>
                                </td>
                                <td class="px-6 py-4">
                                    <span 
                                        class="inline-flex items-center justify-center w-8 h-8 rounded-full text-sm font-semibold"
                                        :class="flow.findings && flow.findings.length > 0 ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500'"
                                        x-text="flow.findings ? flow.findings.length : 0"
                                    ></span>
                                </td>
                            </tr>
                        </template>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Diagram Tab -->
        <div x-show="activeTab === 'diagram'" x-cloak>
            <div class="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
                <h3 class="text-lg font-semibold text-slate-800 mb-4">Data Flow Diagram</h3>
                <div class="bg-slate-50 rounded-lg p-4 text-center">
                    <img src="dfd.png" alt="Data Flow Diagram" class="max-w-full mx-auto rounded shadow-sm" onerror="this.parentElement.innerHTML='<p class=\\'text-slate-500\\'>DFD image not found. Generate with: make dfd</p>'">
                </div>
            </div>
        </div>

    </main>

    <!-- Footer -->
    <footer class="border-t border-slate-200 mt-12 py-8 text-center text-sm text-slate-500">
        Generated with <a href="https://pypi.org/project/pytm/" class="text-blue-500 hover:underline">pytm</a> | 
        Cyber Range Threat Model
    </footer>

    <script>
        function threatModel() {{
            const data = {{
                activeTab: 'findings',
                search: '',
                severityFilter: '',
                showModal: false,
                selectedFinding: null,
                findings: {escape_for_script(findings_sorted)},
                elements: {escape_for_script(elements)},
                dataflows: {escape_for_script(dataflows)},
                
                get filteredFindings() {{
                    return this.findings.filter(f => {{
                        const matchesSearch = !this.search || 
                            f.description?.toLowerCase().includes(this.search.toLowerCase()) ||
                            f.target?.toLowerCase().includes(this.search.toLowerCase()) ||
                            f.threat_id?.toLowerCase().includes(this.search.toLowerCase());
                        const matchesSeverity = !this.severityFilter || f.severity === this.severityFilter;
                        return matchesSearch && matchesSeverity;
                    }});
                }},
                
                getSeverityBg(severity) {{
                    const colors = {{
                        'Very High': 'bg-red-600',
                        'High': 'bg-orange-500',
                        'Medium': 'bg-yellow-500',
                        'Low': 'bg-blue-500',
                        'Very Low': 'bg-gray-400'
                    }};
                    return colors[severity] || 'bg-gray-500';
                }},
                
                getElementFindingCount(elementName) {{
                    return this.findings.filter(f => f.target === elementName).length;
                }}
            }};
            console.log('Threat model initialized with', data.findings.length, 'findings');
            return data;
        }}
    </script>
</body>
</html>'''
    
    return html


def main():
    print("Generating threat model data...", file=sys.stderr)
    data = run_pytm_json()
    
    print("Building HTML report...", file=sys.stderr)
    html = generate_html(data)
    
    output_path = "output/report.html"
    with open(output_path, "w") as f:
        f.write(html)
    
    print(f"Report generated: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
