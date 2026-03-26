import "dotenv/config";
import type { NormalizedIssue, Scope } from "./types.js";
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Get the directory of this file
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Logging helper - writes to both stderr and log file
const LOG_FILE = path.join(__dirname, '..', 'snyk-mcp-server.log');
const log = (message: string, data?: any) => {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] [snyk.ts] ${message}${data ? ' ' + JSON.stringify(data, null, 2) : ''}\n`;

  // Write to stderr (for terminal viewing)
  console.error(logMessage.trim());

  // Write to log file
  try {
    fs.appendFileSync(LOG_FILE, logMessage);
  } catch (err) {
    console.error('Failed to write to log file:', err);
  }
};

const BASE_URL = "https://api.snyk.io/rest";
const TOKEN = process.env.SNYK_TOKEN!;
const ORG_ID = process.env.SNYK_ORG_ID!;

// Only log environment info once at startup
let hasLoggedEnv = false;
if (!hasLoggedEnv) {
  log('Snyk module loaded', {
    BASE_URL,
    TOKEN_SET: TOKEN ? '***SET***' : 'NOT SET',
    ORG_ID_SET: ORG_ID ? '***SET***' : 'NOT SET',
  });
  hasLoggedEnv = true;
}

if (!TOKEN) {
  log('ERROR: SNYK_TOKEN is not set!');
}

if (!ORG_ID) {
  log('ERROR: SNYK_ORG_ID is not set!');
}

const headers = {
  Authorization: `token ${TOKEN}`,
  "Content-Type": "application/vnd.api+json",
};

function detectScope(manifest: string): Scope {
  if (!manifest) return "UNKNOWN";

  if (manifest.includes("webapp") || manifest.includes("package.json")) {
    return "FE";
  }

  if (manifest.includes("pom.xml") || manifest.includes("build.gradle")) {
    return "BE";
  }

  return "UNKNOWN";
}

function detectScopeFromProjectType(projectType: string): Scope {
  if (!projectType || projectType === "unknown") return "UNKNOWN";

  const type = projectType.toLowerCase();

  // Backend project types
  if (type === "maven" ||
      type === "gradle" ||
      type === "sbt" ||
      type === "pip" ||
      type === "poetry" ||
      type === "rubygems" ||
      type === "gomodules" ||
      type === "golangdep") {
    return "BE";
  }

  // Frontend project types
  if (type === "npm" ||
      type === "yarn" ||
      type === "pnpm" ||
      type === "yarn-workspace") {
    return "FE";
  }

  return "UNKNOWN";
}

export async function listProjects(): Promise<any[]> {
  log('listProjects: STARTING');

  let allProjects: any[] = [];
  let nextUrl: string | null = `${BASE_URL}/orgs/${ORG_ID}/projects?version=2024-01-23&limit=100`;
  let pageNumber = 1;

  try {
    while (nextUrl) {
      log(`\n${'='.repeat(80)}`);
      log(`📞 API CALL #${pageNumber}: ${nextUrl}`);
      log(`${'='.repeat(80)}\n`);

      log(`🌐 === HTTP REQUEST (Page ${pageNumber}) ===`, {
        method: 'GET',
        url: nextUrl,
      });

      const requestStartTime = Date.now();
      const res: Response = await fetch(nextUrl, { headers });
      const requestDuration = Date.now() - requestStartTime;

      // LOG RESPONSE
      log(`📥 === HTTP RESPONSE (Page ${pageNumber}) ===`, {
        status: res.status,
        statusText: res.statusText,
        ok: res.ok,
        duration: `${requestDuration}ms`,
      });

      if (!res.ok) {
        const errorBody = await res.text();
        log('❌ API ERROR - Response Body:', errorBody);
        throw new Error(`Snyk API error: ${res.status} - ${errorBody}`);
      }

      const data: any = await res.json();
      const projectCount = (data.data || []).length;

      // LOG RESPONSE BODY SUMMARY
      log(`📦 Response Body Summary (Page ${pageNumber}):`, {
        projectsInPage: projectCount,
        totalSoFar: allProjects.length + projectCount,
        sampleProject: data.data?.[0] ? {
          id: data.data[0].id,
          name: data.data[0].attributes?.name,
          type: data.data[0].attributes?.type
        } : null,
        hasNextPage: !!data.links?.next
      });

      // Add projects from this page
      const projects = (data.data || []).map((item: any) => ({
        id: item.id,
        name: item.attributes?.name || "unknown",
        type: item.attributes?.type || "unknown",
        origin: item.attributes?.origin || "unknown",
        created: item.attributes?.created,
      }));
      allProjects.push(...projects);

      // Check for next page - handle relative URLs from API
      const nextLink: string | undefined = data.links?.next;
      if (nextLink) {
        // If next link is relative (starts with /rest), make it absolute
        nextUrl = nextLink.startsWith('/rest')
          ? `https://api.snyk.io${nextLink}`
          : nextLink;
      } else {
        nextUrl = null;
      }
      pageNumber++;

      // Safety limit to prevent infinite loops
      if (pageNumber > 50) {
        log('⚠️ Reached safety limit of 50 pages, stopping pagination');
        break;
      }
    }

    log('✅ listProjects: Success', {
      totalProjects: allProjects.length,
      totalPages: pageNumber - 1
    });

    return allProjects;
  } catch (error) {
    log('❌ listProjects: Exception', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    throw error;
  }
}

export async function getIssuesForProject(
  projectId: string,
  severity: "critical" | "high" | "medium" | "low" | undefined = undefined,
  projectName?: string
): Promise<NormalizedIssue[]> {
  log('getIssuesForProject: STARTING', { projectId, severity: severity || 'all' });

  let allRawIssues: any[] = [];
  let nextUrl: string | null = `${BASE_URL}/orgs/${ORG_ID}/issues?version=2024-01-23&limit=100`;
  let pageNumber = 1;

  // Add project filtering if projectId is provided and not "org"
  if (projectId && projectId !== "org") {
    nextUrl += `&scan_item.id=${projectId}&scan_item.type=project`;
  }

  // Add severity filter
  if (severity) {
    nextUrl += `&effective_severity_level=${severity}`;
  }

  try {
    while (nextUrl) {
      log(`\n${'='.repeat(80)}`);
      log(`📞 API CALL #${pageNumber}: ${nextUrl}`);
      log(`${'='.repeat(80)}\n`);

      log(`🌐 === HTTP REQUEST (Page ${pageNumber}) ===`, {
        method: 'GET',
        url: nextUrl,
        filters: {
          projectId: projectId || 'org-wide',
          severity: severity || 'all'
        }
      });

      const requestStartTime = Date.now();
      const res: Response = await fetch(nextUrl, { headers });
      const requestDuration = Date.now() - requestStartTime;

      // LOG RESPONSE
      log(`📥 === HTTP RESPONSE (Page ${pageNumber}) ===`, {
        status: res.status,
        statusText: res.statusText,
        ok: res.ok,
        duration: `${requestDuration}ms`,
      });

      if (!res.ok) {
        const errorBody = await res.text();
        log('❌ API ERROR - Response Body:', errorBody);
        throw new Error(`Snyk API error: ${res.status} - ${errorBody}`);
      }

      const data: any = await res.json();
      const issueCount = (data.data || []).length;

      // LOG ALL SEVERITIES FROM RAW API RESPONSE
      const rawSeverities = (data.data || []).map((item: any) =>
        item.attributes?.effective_severity_level || 'unknown'
      );
      const severityCounts = rawSeverities.reduce((acc: any, sev: string) => {
        acc[sev] = (acc[sev] || 0) + 1;
        return acc;
      }, {});

      // LOG RESPONSE BODY SUMMARY
      log(`📦 Response Body Summary (Page ${pageNumber}):`, {
        issuesInPage: issueCount,
        totalSoFar: allRawIssues.length + issueCount,
        severityCounts: severityCounts,
        sampleIssue: data.data?.[0] ? {
          title: data.data[0].attributes?.title,
          severity: data.data[0].attributes?.effective_severity_level
        } : null,
        hasNextPage: !!data.links?.next
      });

      // Collect raw issue data (will map after fetching project types)
      allRawIssues.push(...(data.data || []));

      // Check for next page - handle relative URLs from API
      const nextLink: string | undefined = data.links?.next;
      if (nextLink) {
        // If next link is relative (starts with /rest), make it absolute
        nextUrl = nextLink.startsWith('/rest')
          ? `https://api.snyk.io${nextLink}`
          : nextLink;
      } else {
        nextUrl = null;
      }
      pageNumber++;

      // Safety limit to prevent infinite loops
      if (pageNumber > 50) {
        log('⚠️ Reached safety limit of 50 pages, stopping pagination');
        break;
      }
    }

    // After pagination completes, extract unique project IDs and fetch their types
    log('Extracting unique project IDs for scope detection');
    const uniqueProjectIds = new Set<string>();
    for (const item of allRawIssues) {
      const scanItemId = item.relationships?.scan_item?.data?.id || projectId;
      if (scanItemId && scanItemId !== "org") {
        uniqueProjectIds.add(scanItemId);
      }
    }

    log('Fetching project types for scope detection', { uniqueProjectCount: uniqueProjectIds.size });

    // Build a map of projectId -> projectType and projectId -> projectName
    const projectTypeMap = new Map<string, string>();
    const projectNameMap = new Map<string, string>();
    await Promise.all(
      Array.from(uniqueProjectIds).map(async (pid) => {
        try {
          const projectUrl = `${BASE_URL}/orgs/${ORG_ID}/projects/${pid}?version=2024-01-23`;
          const projectRes = await fetch(projectUrl, { headers });
          if (projectRes.ok) {
            const projectData = await projectRes.json();
            const type = projectData.data?.attributes?.type || "unknown";
            const name = projectData.data?.attributes?.name || "unknown";
            projectTypeMap.set(pid, type);
            projectNameMap.set(pid, name);
            log('Fetched project info', { projectId: pid, type, name });
          } else {
            projectTypeMap.set(pid, "unknown");
            projectNameMap.set(pid, "unknown");
            log('Failed to fetch project info - non-ok response', { projectId: pid });
          }
        } catch (error) {
          log('Failed to fetch project info - exception', { projectId: pid, error });
          projectTypeMap.set(pid, "unknown");
          projectNameMap.set(pid, "unknown");
        }
      })
    );

    log('Project type map built', {
      totalProjects: projectTypeMap.size,
      types: Array.from(projectTypeMap.entries()).reduce((acc, [id, type]) => {
        acc[type] = (acc[type] || 0) + 1;
        return acc;
      }, {} as Record<string, number>)
    });

    // Now map all raw issues to normalized format with correct scope
    const allIssues = allRawIssues.map((item: any) => {
      const attrs = item.attributes || {};

      // Extract package info from coordinates
      const coords = attrs.coordinates?.[0] || {};
      const representations = coords.representations?.[0] || {};
      const dependency = representations?.dependency;
      const packageName = dependency?.package_name || "unknown";
      const packageVersion = dependency?.package_version || null;

      // Extract project ID from relationships
      const scanItemId = item.relationships?.scan_item?.data?.id || projectId;

      // Look up the specific project type and name for this issue
      const issueProjectType = projectTypeMap.get(scanItemId) || "unknown";
      const issueProjectFullName = projectNameMap.get(scanItemId) || projectName || "unknown";

      // Extract just the repo name (e.g., "my-api" from "org-name/my-api:pom.xml")
      let repoName = "unknown";
      if (issueProjectFullName !== "unknown") {
        const parts = issueProjectFullName.split('/');
        if (parts.length >= 2) {
          const repoWithFile = parts[1] || '';
          repoName = repoWithFile.split(':')[0] || repoWithFile;
        } else {
          // If no slash, just take the first part before colon
          repoName = issueProjectFullName.split(':')[0] || issueProjectFullName;
        }
      }

      const scope = detectScopeFromProjectType(issueProjectType);

      return {
        project: repoName,
        projectFullName: issueProjectFullName,
        projectId: scanItemId,
        title: attrs.title || "unknown",
        severity: (attrs.effective_severity_level || "").toLowerCase(),
        dependency: packageName,
        version: packageVersion,
        fixedIn: null,
        vulnId: attrs.key || item.id,
        cve: attrs.problems?.map((p: any) => p.id).filter((id: string) => id?.startsWith('CVE-')) || [],
        manifest: "unknown",
        scope: scope,
        snykUrl: attrs.problems?.[0]?.url || null,
      };
    });

    // Log scope distribution
    const scopeCounts = allIssues.reduce((acc: any, issue: any) => {
      acc[issue.scope] = (acc[issue.scope] || 0) + 1;
      return acc;
    }, {});

    log('✅ getIssuesForProject: Success', {
      projectId,
      severity: severity || 'all',
      totalIssues: allIssues.length,
      totalPages: pageNumber - 1,
      scopeDistribution: scopeCounts
    });

    return allIssues;

  } catch (error) {
    log('❌ getIssuesForProject: Exception', {
      projectId,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    throw error;
  }
}