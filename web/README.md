# Go Auth System - Admin Dashboard

A modern, responsive admin dashboard for the Go Auth System built with React, TypeScript, and Tailwind CSS.

## Features

- **User Management**: View, search, and manage user accounts with bulk actions
- **Role Management**: Create and manage roles and permissions
- **Session Management**: Monitor and terminate active user sessions
- **System Monitoring**: Real-time system health and performance metrics
- **Audit Logging**: Comprehensive audit trail with filtering and search
- **Configuration Management**: Dynamic system configuration with validation
- **Alert System**: Real-time alerts with severity levels and notifications
- **Notification Settings**: Configure email, Slack, and SMS notifications

## Technology Stack

- **React 18** - Modern React with hooks and concurrent features
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Utility-first CSS framework
- **React Query** - Data fetching and caching
- **React Hook Form** - Form handling with validation
- **Recharts** - Data visualization and charts
- **Lucide React** - Beautiful icons
- **React Hot Toast** - Toast notifications
- **Vite** - Fast build tool and dev server
- **Playwright** - End-to-end testing

## Getting Started

### Prerequisites

- Node.js 18 or higher
- npm or yarn

### Installation

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm run dev
```

3. Open [http://localhost:3000](http://localhost:3000) in your browser

### Building for Production

```bash
npm run build
```

### Running Tests

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e
```

## Project Structure

```
src/
├── components/          # Reusable UI components
│   └── Layout.tsx      # Main layout with navigation
├── pages/              # Page components
│   ├── Dashboard.tsx   # Main dashboard with metrics
│   ├── Users.tsx       # User management
│   ├── Roles.tsx       # Role management
│   ├── Sessions.tsx    # Session management
│   ├── AuditLogs.tsx   # Audit log viewer
│   ├── SystemHealth.tsx # System health monitoring
│   ├── Configuration.tsx # System configuration
│   ├── Alerts.tsx      # Alert management
│   └── NotificationSettings.tsx # Notification settings
├── lib/                # Utilities and API client
│   ├── api.ts          # API client with axios
│   └── utils.ts        # Utility functions
├── types/              # TypeScript type definitions
│   └── api.ts          # API response types
├── App.tsx             # Main app component
├── main.tsx            # App entry point
└── index.css           # Global styles
```

## API Integration

The dashboard integrates with the Go Auth System backend API:

- **Authentication**: JWT-based authentication
- **Real-time Updates**: Automatic data refresh for metrics and alerts
- **Error Handling**: Comprehensive error handling with user feedback
- **Type Safety**: Full TypeScript coverage for API responses

## Features in Detail

### Dashboard
- Real-time system metrics and KPIs
- Interactive charts for user trends
- System health status indicators
- Critical alert notifications

### User Management
- User search and filtering
- Bulk user operations (lock, unlock, verify, etc.)
- User role assignments
- Account status management

### System Monitoring
- Component health status
- Performance metrics
- Resource utilization
- Real-time updates

### Configuration Management
- Dynamic configuration updates
- Form validation
- Hot reloading support
- Environment-specific settings

### Alert System
- Real-time alert notifications
- Severity-based filtering
- Alert resolution tracking
- Custom alert creation

## Development

### Code Style

The project uses ESLint and Prettier for code formatting:

```bash
npm run lint
npm run lint:fix
```

### Testing

- **Unit Tests**: Vitest for component and utility testing
- **E2E Tests**: Playwright for full application testing
- **API Mocking**: Mock Service Worker for API testing

### Environment Variables

Create a `.env.local` file for local development:

```env
VITE_API_BASE_URL=http://localhost:8080/api/v1
```

## Deployment

### Docker

Build and run with Docker:

```bash
docker build -t go-auth-admin .
docker run -p 80:80 go-auth-admin
```

### Production Considerations

- Enable HTTPS in production
- Configure proper CORS settings
- Set up monitoring and logging
- Use environment-specific configurations
- Enable security headers

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Run the test suite
6. Submit a pull request

## License

This project is part of the Go Auth System and follows the same license terms.