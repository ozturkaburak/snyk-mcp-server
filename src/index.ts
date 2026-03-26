import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { getIssuesForProject, listProjects } from "./snyk.js";

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
  const logMessage = `[${timestamp}] ${message}${data ? ' ' + JSON.stringify(data, null, 2) : ''}\n`;

  // Write to stderr (for terminal viewing)
  console.error(logMessage.trim());

  // Write to log file
  try {
    fs.appendFileSync(LOG_FILE, logMessage);
  } catch (err) {
    console.error('Failed to write to log file:', err);
  }
};

log('=== Snyk MCP Server Starting ===');
log('Environment Variables:', {
  SNYK_TOKEN: process.env.SNYK_TOKEN ? '***SET***' : 'NOT SET',
  SNYK_ORG_ID: process.env.SNYK_ORG_ID ? '***SET***' : 'NOT SET',
});

const server = new McpServer({
  name: "snyk-mcp-server",
  version: "0.1.0",
});

log('MCP Server instance created');

/**
 * TOOL 1: list_snyk_projects
 */
server.tool(
  "list_snyk_projects",
  {},
  async () => {
    log('🚀 Tool called: list_snyk_projects');

    try {
      const projects = await listProjects();
      log('✅ list_snyk_projects completed', {
        projectCount: projects.length
      });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ projects }, null, 2)
          }
        ]
      };
    } catch (error) {
      log('❌ list_snyk_projects ERROR', {
        errorMessage: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }
);

log('Registered tool: list_snyk_projects');

/**
 * TOOL 2: get_snyk_issues
 * Get issues for specified projects, optionally filtered by severity and scope
 */
server.tool(
  "get_snyk_issues",
  {
    projectIds: z.array(z.string()).optional(),
    projectNames: z.array(z.string()).optional(),
    severity: z.enum(["critical", "high", "medium", "low"]).optional(),
    scope: z.enum(["FE", "BE", "UNKNOWN"]).optional(),
  },
  async ({ projectIds, projectNames, severity, scope }) => {
    log('Tool called: get_snyk_issues', { projectIds, projectNames, severity, scope });

    try {
      // If project names are provided, first get all projects and find matching IDs
      let targetProjectIds = projectIds || [];
      let matchedProjects: any[] = [];

      if (projectNames && projectNames.length > 0) {
        log('Fetching projects to match names');
        const allProjects = await listProjects();

        for (const searchName of projectNames) {
          const searchNameLower = searchName.toLowerCase();

          // Find ALL projects that match (support partial matching)
          const matches = allProjects.filter(p => {
            const projectNameLower = p.name.toLowerCase();

            // Extract the base repo name without file suffix (e.g., "my-app" from "org-name/my-app:package.json")
            const parts = p.name.split('/');
            if (parts.length >= 2) {
              const repoWithFile = parts[1] || '';
              const repoName = repoWithFile.split(':')[0] || '';

              // Match if repo name contains search term
              if (repoName.toLowerCase().includes(searchNameLower)) {
                return true;
              }
            }

            // Also match full project name contains search term
            if (projectNameLower.includes(searchNameLower)) {
              return true;
            }

            return false;
          });

          if (matches.length > 0) {
            // Prioritize manifest-based projects over SAST projects
            // Manifest projects (gradle, maven, npm, yarn, etc.) have actual dependency data
            // SAST projects are code analysis only and may not have vulnerability data
            const prioritizedMatches = matches.sort((a, b) => {
              const manifestTypes = ['gradle', 'maven', 'npm', 'yarn', 'pnpm', 'pip', 'poetry', 'gomodules', 'sbt'];
              const aIsManifest = manifestTypes.includes(a.type.toLowerCase());
              const bIsManifest = manifestTypes.includes(b.type.toLowerCase());

              // Manifest projects come first
              if (aIsManifest && !bIsManifest) return -1;
              if (!aIsManifest && bIsManifest) return 1;

              return 0;
            });

            matchedProjects.push(...prioritizedMatches);
            log(`✅ Found ${matches.length} match(es) for "${searchName}":`, {
              projects: prioritizedMatches.map(m => ({ name: m.name, id: m.id, type: m.type }))
            });
          } else {
            log(`⚠️ No match found for "${searchName}"`);
          }
        }

        targetProjectIds = [...targetProjectIds, ...matchedProjects.map(p => p.id)];
      }

      // If no specific projects, fetch org-wide
      if (targetProjectIds.length === 0) {
        log('No specific projects - fetching org-wide issues');
        let issues = await getIssuesForProject("org", severity as any);

        // Apply scope filter if provided
        if (scope) {
          const beforeFilter = issues.length;
          issues = issues.filter(issue => issue.scope === scope);
          log('Applied scope filter', { scope, before: beforeFilter, after: issues.length });
        }

        log('get_snyk_issues completed (org-wide)', { totalIssues: issues.length });
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({ issues }, null, 2)
          }]
        };
      }

      // Log all matched projects before making API calls
      log('=== MATCHED PROJECTS - WILL FETCH ISSUES ===', {
        totalMatched: matchedProjects.length,
        projects: matchedProjects.map(p => ({
          name: p.name,
          id: p.id,
          type: p.type
        }))
      });

      // Fetch issues for each project separately
      let allIssues: any[] = [];

      for (let i = 0; i < targetProjectIds.length; i++) {
        const projectId = targetProjectIds[i]!;
        const projectName = matchedProjects[i]?.name || 'unknown';

        log(`📡 About to fetch issues for Project ${i + 1}/${targetProjectIds.length}:`, {
          projectName,
          projectId,
          severity: severity || 'all'
        });

        const projectIssues = await getIssuesForProject(projectId, (severity ?? undefined) as any, projectName);
        log(`✅ Got ${projectIssues.length} issues for ${projectName}`);
        allIssues.push(...projectIssues);
      }

      // Apply scope filter if provided
      if (scope) {
        const beforeFilter = allIssues.length;
        allIssues = allIssues.filter(issue => issue.scope === scope);
        log('Applied scope filter', { scope, before: beforeFilter, after: allIssues.length });
      }

      log('get_snyk_issues completed', {
        totalProjects: targetProjectIds.length,
        totalIssues: allIssues.length
      });

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ issues: allIssues }, null, 2)
          }
        ]
      };
    } catch (error) {
      log('get_snyk_issues ERROR', { error: error instanceof Error ? error.message : error });
      throw error;
    }
  }
);

log('Registered tool: get_snyk_issues');

/**
 * TOOL 3: get_project_issues
 * Get issues for a specific project by name, with optional severity and scope filter
 */
server.tool(
  "get_project_issues",
  {
    projectName: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]).optional(),
    scope: z.enum(["FE", "BE", "UNKNOWN"]).optional(),
  },
  async ({ projectName, severity, scope }) => {
    // Apply default value for severity
    const effectiveSeverity = severity || "critical";

    log('🚀 Tool called: get_project_issues', { projectName, severity: effectiveSeverity, scope });

    try {
      // Step 1: Fetch all projects (pagination handled internally)
      log('📋 Fetching all projects to find match...');
      const allProjects = await listProjects();
      log(`✅ Fetched ${allProjects.length} total projects`);

      // Step 2: Find matching project (case-insensitive, flexible matching)
      const searchNameLower = projectName.toLowerCase();

      // First, find ALL potential matches
      const potentialMatches = allProjects.filter(p => {
        const projectNameLower = p.name.toLowerCase();

        // Try exact match first
        if (projectNameLower === searchNameLower) {
          return true;
        }

        // Try matching the full name contains the search term
        if (projectNameLower.includes(searchNameLower)) {
          return true;
        }

        // Try matching short name (last segment after /)
        const parts = p.name.split('/');
        const shortName = parts[parts.length - 1];
        if (shortName.toLowerCase() === searchNameLower) {
          return true;
        }

        // Try matching repo name (second segment, e.g., "my-service" from "org-name/my-service:package.json")
        if (parts.length >= 2) {
          const repoName = parts[1]!.split(':')[0];
          if (repoName && repoName.toLowerCase() === searchNameLower) {
            return true;
          }
        }

        return false;
      });

      // Prioritize manifest-based projects over SAST projects
      // Manifest projects (gradle, maven, npm, yarn, etc.) have actual dependency vulnerability data
      // SAST projects are code analysis only and may not have the same vulnerability information
      const matchedProject = potentialMatches.sort((a, b) => {
        const manifestTypes = ['gradle', 'maven', 'npm', 'yarn', 'pnpm', 'pip', 'poetry', 'gomodules', 'sbt'];
        const aIsManifest = manifestTypes.includes(a.type.toLowerCase());
        const bIsManifest = manifestTypes.includes(b.type.toLowerCase());

        // Manifest projects come first
        if (aIsManifest && !bIsManifest) return -1;
        if (!aIsManifest && bIsManifest) return 1;

        return 0;
      })[0];

      // Step 3: Handle no match
      if (!matchedProject) {
        log(`⚠️ No project found matching "${projectName}"`);
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              error: `Project "${projectName}" not found`,
              matchedProject: null,
              issues: []
            }, null, 2)
          }]
        };
      }

      // Step 4: Log matched project details
      log('✅ Project matched:', {
        projectName: matchedProject.name,
        projectId: matchedProject.id,
        projectType: matchedProject.type
      });

      // Step 5: Fetch issues for the matched project
      log(`📡 Fetching issues with severity filter: ${effectiveSeverity || 'ALL'}...`);
      let issues = await getIssuesForProject(matchedProject.id, effectiveSeverity, matchedProject.name);

      // Apply scope filter if provided
      const beforeScopeFilter = issues.length;
      if (scope) {
        issues = issues.filter(issue => issue.scope === scope);
        log('Applied scope filter', { scope, before: beforeScopeFilter, after: issues.length });
      }

      // Count ACTUAL severities from API response (NOT our parameter!)
      const apiSeverityCounts = issues.reduce((acc: any, issue: any) => {
        const actualSeverity = issue.severity || 'unknown';
        acc[actualSeverity] = (acc[actualSeverity] || 0) + 1;
        return acc;
      }, {});

      log('✅ get_project_issues completed', {
        projectName: matchedProject.name,
        projectId: matchedProject.id,
        requestedFilter: effectiveSeverity || 'ALL',
        scopeFilter: scope || 'ALL',
        totalIssuesFromAPI: issues.length,
        apiReturnedSeverities: apiSeverityCounts
      });

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            matchedProject: {
              name: matchedProject.name,
              id: matchedProject.id,
              type: matchedProject.type
            },
            requestedFilter: effectiveSeverity || 'ALL',
            scopeFilter: scope || 'ALL',
            totalIssuesFromAPI: issues.length,
            apiReturnedSeverities: apiSeverityCounts,
            issues
          }, null, 2)
        }]
      };
    } catch (error) {
      log('❌ get_project_issues ERROR', {
        projectName,
        severity,
        errorMessage: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }
);

log('Registered tool: get_project_issues');

async function main() {
  log('Initializing stdio transport...');
  const transport = new StdioServerTransport();

  log('Connecting MCP server...');
  await server.connect(transport);

  log('=== Snyk MCP Server Ready ===');
  log('Server is now listening for requests');
}

main().catch((err) => {
  log('FATAL ERROR during startup', { error: err.message, stack: err.stack });
  console.error(err);
  process.exit(1);
});

// Graceful shutdown handlers
process.on('SIGINT', () => {
  log('Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  log('Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  log('UNCAUGHT EXCEPTION', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  log('UNHANDLED REJECTION', { reason });
  process.exit(1);
});