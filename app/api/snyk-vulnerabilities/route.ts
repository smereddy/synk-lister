import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const { orgId, apiToken } = await request.json();

    if (!orgId || !apiToken) {
      return NextResponse.json({ error: 'Organization ID and API Token are required' }, { status: 400 });
    }

    console.log(`Fetching vulnerabilities for organization: ${orgId}`);
    const baseUrl = "https://api.snyk.io/rest";
    const endpoint = `/orgs/${orgId}/issues`;

    const params = new URLSearchParams({
      'version': '2024-06-10',
      'context[page]': 'issues',
      'issue_status': '["Open"]',
      'issues_table_issues_detail_cols': 'SCORE|ASSET & SOURCE CODE|EXPLOIT MATURITY|TARGET & PROJECT|PROJECT ORIGIN|SNYK PRODUCT',
      'issues_table_issues_detail_sort': 'ISSUE_SEVERITY_RANK DESC'
    });

    const response = await fetch(`${baseUrl}${endpoint}?${params.toString()}`, {
      method: 'GET',
      headers: {
        'Authorization': `token ${apiToken}`,
        'Content-Type': 'application/vnd.api+json'
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Snyk API error: ${response.status} ${response.statusText}`, errorText);
      return NextResponse.json({ error: `Failed to fetch vulnerabilities from Snyk API: ${response.status} ${response.statusText}` }, { status: response.status });
    }

    const data = await response.json();
    console.log('Received data from Snyk API:', JSON.stringify(data, null, 2));

    if (!data.data || !Array.isArray(data.data)) {
      console.error('Unexpected response structure from Snyk API:', data);
      return NextResponse.json({ error: 'Unexpected response structure from Snyk API' }, { status: 500 });
    }

    // Process the vulnerabilities and extract necessary information
    const processedVulnerabilities = data.data.map((issue: any) => ({
      id: issue.id,
      title: issue.attributes.title,
      severity: issue.attributes.severity,
      description: issue.attributes.description,
      product: issue.attributes.product,
      projectName: issue.attributes.project_name,
      packageName: issue.attributes.package_name,
      version: issue.attributes.version,
      exploitMaturity: issue.attributes.exploit_maturity,
      fixInfo: issue.attributes.fix_info ? issue.attributes.fix_info.steps : 'No fix information available',
    }));

    console.log(`Processed ${processedVulnerabilities.length} vulnerabilities`);
    return NextResponse.json({ vulnerabilities: processedVulnerabilities });
  } catch (error) {
    console.error('Error in Snyk vulnerabilities API route:', error);
    return NextResponse.json({ error: error instanceof Error ? error.message : 'An unexpected error occurred' }, { status: 500 });
  }
}