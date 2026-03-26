# Snyk MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io/)

A Model Context Protocol (MCP) server that integrates Snyk security scanning with Claude Code and other MCP clients.

## Features

- 🔍 List all Snyk projects in your organization
- 🐛 Query security issues by severity (critical, high, medium, low)
- 🎯 Filter issues by project name or ID
- 🔧 Scope filtering (Frontend/Backend)
- 📊 Get normalized issue data with CVEs, dependencies, and fix information

## Prerequisites

- Node.js 18+
- A Snyk account with API access
- Snyk organization ID

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ozturkaburak/snyk-mcp-server.git
cd snyk-mcp-server
```

2. Install dependencies:
```bash
npm install
```

3. Create `.env` file from template:
```bash
cp .env.example .env
```

4. Configure your Snyk credentials in `.env`:
```env
SNYK_TOKEN=your_snyk_token_here
SNYK_ORG_ID=your-org-id_here
```

## Usage

### Build the project
```bash
npm run build
```

### Run in production mode
```bash
npm start
```

### Run in development mode
```bash
npm run dev
```

## MCP Tools

This server provides three MCP tools:

### 1. `list_snyk_projects`
Lists all projects in your Snyk organization.

**Parameters:** None

**Example:**
```typescript
list_snyk_projects()
```

### 2. `get_project_issues`
Get all issues for a specific project.

**Parameters:**
- `projectId` (required): The Snyk project ID
- `severity` (optional): Filter by severity - "critical", "high", "medium", or "low"

**Example:**
```typescript
get_project_issues({
  projectId: "abc-123-def-456",
  severity: "critical"
})
```

### 3. `get_snyk_issues`
Get issues across multiple projects with advanced filtering.

**Parameters:**
- `projectIds` (optional): Array of project IDs
- `projectNames` (optional): Array of project names (fuzzy matching)
- `severity` (optional): Filter by severity
- `scope` (optional): "FE" (Frontend), "BE" (Backend), or "UNKNOWN"

**Examples:**
```typescript
// Get all critical backend issues across multiple microservices
get_snyk_issues({
  projectNames: [
    "api-gateway",
    "auth-service",
    "payment-service",
    "user-service",
    "notification-service"
  ],
  severity: "critical",
  scope: "BE"
})

// Get high severity frontend issues
get_snyk_issues({
  projectNames: ["web-app", "mobile-app"],
  severity: "high",
  scope: "FE"
})

// Get all critical issues without filtering by project
get_snyk_issues({
  severity: "critical"
})
```

## Integration with Claude Code

Add this to your Claude Code MCP settings (`.claude/mcp_settings.json`):

```json
{
  "mcpServers": {
    "snyk-local": {
      "command": "node",
      "args": ["/path/to/snyk-mcp-server/dist/index.js"],
      "env": {
        "SNYK_TOKEN": "your-snyk-token",
        "SNYK_ORG_ID": "your-org-id"
      }
    }
  }
}
```

## Configuration

The server uses environment variables for configuration:

| Variable | Description | Required |
|----------|-------------|----------|
| `SNYK_TOKEN` | Your Snyk API token | Yes |
| `SNYK_ORG_ID` | Your Snyk organization ID | Yes |

### Getting Your Credentials

1. **SNYK_TOKEN**: Get from [Snyk Account Settings](https://app.snyk.io/account)
2. **SNYK_ORG_ID**: Find in your org settings URL: `https://app.snyk.io/org/your-org-id/manage/settings`

## Project Structure

```
snyk-mcp-server/
├── src/
│   ├── index.ts      # MCP server implementation
│   ├── snyk.ts       # Snyk API client
│   └── types.ts      # TypeScript type definitions
├── dist/             # Compiled JavaScript
├── .env.example      # Environment template
└── package.json
```

## Development

### TypeScript Development
```bash
npm run dev
```

### Building
```bash
npm run build
```

## API Documentation

See [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) for detailed Snyk REST API documentation.

## Troubleshooting

### Common Issues

**"SNYK_TOKEN not set"**
- Make sure you created `.env` file with your token

**"No projects found"**
- Verify your `SNYK_ORG_ID` is correct
- Check your token has access to the organization

**"Critical issues not showing"**
- Some issues may not be synced to REST API yet
- Check the issue in Snyk UI to verify it exists
- See [FINDINGS_REPORT.md](./FINDINGS_REPORT.md) for analysis

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

ISC

## Related Resources

- [Snyk REST API Documentation](https://apidocs.snyk.io/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Claude Code](https://www.anthropic.com/claude/code)

## Author

Built with ❤️ for secure software development
