package deployment

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// TestKubernetesManifests tests the Kubernetes manifest files
func TestKubernetesManifests(t *testing.T) {
	manifestsDir := "../../k8s"

	t.Run("ValidateManifestSyntax", func(t *testing.T) {
		manifestFiles := []string{
			"namespace.yaml",
			"configmap.yaml",
			"secret.yaml",
			"postgres-deployment.yaml",
			"redis-deployment.yaml",
			"auth-deployment.yaml",
			"ingress.yaml",
			"monitoring.yaml",
		}

		for _, file := range manifestFiles {
			t.Run(file, func(t *testing.T) {
				filePath := filepath.Join(manifestsDir, file)
				data, err := os.ReadFile(filePath)
				require.NoError(t, err, "Failed to read manifest file %s", file)

				// Parse YAML to ensure it's valid
				decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
				for {
					var obj map[string]interface{}
					err := decoder.Decode(&obj)
					if err != nil {
						if err.Error() == "EOF" {
							break
						}
						t.Fatalf("Failed to parse YAML in %s: %v", file, err)
					}

					// Basic validation - should have apiVersion and kind
					assert.Contains(t, obj, "apiVersion", "Missing apiVersion in %s", file)
					assert.Contains(t, obj, "kind", "Missing kind in %s", file)
					assert.Contains(t, obj, "metadata", "Missing metadata in %s", file)
				}
			})
		}
	})

	t.Run("ValidateDeploymentSpecs", func(t *testing.T) {
		// Test auth deployment specifically
		filePath := filepath.Join(manifestsDir, "auth-deployment.yaml")
		data, err := os.ReadFile(filePath)
		require.NoError(t, err)

		var deployment appsv1.Deployment
		err = yaml.Unmarshal(data, &deployment)
		require.NoError(t, err)

		// Validate deployment configuration
		assert.Equal(t, "go-auth-system", deployment.Name)
		assert.Equal(t, "go-auth-system", deployment.Namespace)
		assert.Equal(t, int32(3), *deployment.Spec.Replicas)

		// Validate container configuration
		containers := deployment.Spec.Template.Spec.Containers
		require.Len(t, containers, 1)

		container := containers[0]
		assert.Equal(t, "go-auth-system", container.Name)
		assert.Equal(t, "go-auth-system:latest", container.Image)

		// Validate ports
		expectedPorts := []int32{8080, 9090, 8081}
		assert.Len(t, container.Ports, len(expectedPorts))
		for i, port := range container.Ports {
			assert.Equal(t, expectedPorts[i], port.ContainerPort)
		}

		// Validate health checks
		assert.NotNil(t, container.LivenessProbe)
		assert.NotNil(t, container.ReadinessProbe)
		assert.NotNil(t, container.StartupProbe)

		// Validate security context
		assert.NotNil(t, container.SecurityContext)
		assert.Equal(t, false, *container.SecurityContext.AllowPrivilegeEscalation)
		assert.Equal(t, true, *container.SecurityContext.ReadOnlyRootFilesystem)
		assert.Equal(t, true, *container.SecurityContext.RunAsNonRoot)
	})

	t.Run("ValidateServiceSpecs", func(t *testing.T) {
		// Parse the auth deployment file which contains the service
		filePath := filepath.Join(manifestsDir, "auth-deployment.yaml")
		data, err := os.ReadFile(filePath)
		require.NoError(t, err)

		// Split YAML documents
		docs := strings.Split(string(data), "---")

		var service corev1.Service
		for _, doc := range docs {
			if strings.Contains(doc, "kind: Service") {
				err = yaml.Unmarshal([]byte(doc), &service)
				require.NoError(t, err)
				break
			}
		}

		// Validate service configuration
		assert.Equal(t, "go-auth-system-service", service.Name)
		assert.Equal(t, "go-auth-system", service.Namespace)
		assert.Equal(t, corev1.ServiceTypeClusterIP, service.Spec.Type)

		// Validate ports
		expectedPorts := map[string]int32{
			"http":    8080,
			"grpc":    9090,
			"metrics": 8081,
		}

		assert.Len(t, service.Spec.Ports, len(expectedPorts))
		for _, port := range service.Spec.Ports {
			expectedPort, exists := expectedPorts[port.Name]
			assert.True(t, exists, "Unexpected port: %s", port.Name)
			assert.Equal(t, expectedPort, port.Port)
			assert.Equal(t, expectedPort, port.TargetPort.IntVal)
		}
	})
}

// TestKubernetesDeployment tests actual deployment to a Kubernetes cluster
// This test requires a running Kubernetes cluster and kubectl configured
func TestKubernetesDeployment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Kubernetes deployment test in short mode")
	}

	// Skip if no kubeconfig is available
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			t.Skip("Cannot determine home directory for kubeconfig")
		}
		kubeconfig = filepath.Join(homeDir, ".kube", "config")
	}

	if _, err := os.Stat(kubeconfig); os.IsNotExist(err) {
		t.Skip("No kubeconfig found, skipping Kubernetes deployment test")
	}

	// Create Kubernetes client
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Skip("Failed to build kubeconfig: " + err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Skip("Failed to create Kubernetes client: " + err.Error())
	}

	ctx := context.Background()
	namespace := "go-auth-system-test"

	// Clean up function
	cleanup := func() {
		clientset.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	}
	defer cleanup()

	t.Run("DeployToCluster", func(t *testing.T) {
		// Create test namespace
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		}
		_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		require.NoError(t, err)

		// TODO: Apply manifests to the cluster
		// This would involve:
		// 1. Reading manifest files
		// 2. Applying them to the cluster
		// 3. Waiting for deployments to be ready
		// 4. Running health checks
		// 5. Cleaning up

		t.Skip("Full Kubernetes deployment test not yet implemented")
	})
}

// TestHelmChart tests the Helm chart
func TestHelmChart(t *testing.T) {
	chartDir := "../../helm/go-auth-system"

	t.Run("ValidateChartStructure", func(t *testing.T) {
		// Check required files exist
		requiredFiles := []string{
			"Chart.yaml",
			"values.yaml",
			"templates/_helpers.tpl",
			"templates/deployment.yaml",
			"templates/service.yaml",
			"templates/configmap.yaml",
			"templates/secret.yaml",
			"templates/serviceaccount.yaml",
			"templates/ingress.yaml",
			"templates/poddisruptionbudget.yaml",
			"templates/hpa.yaml",
			"templates/servicemonitor.yaml",
		}

		for _, file := range requiredFiles {
			filePath := filepath.Join(chartDir, file)
			_, err := os.Stat(filePath)
			assert.NoError(t, err, "Required file %s does not exist", file)
		}
	})

	t.Run("ValidateChartYaml", func(t *testing.T) {
		filePath := filepath.Join(chartDir, "Chart.yaml")
		data, err := os.ReadFile(filePath)
		require.NoError(t, err)

		var chart map[string]interface{}
		err = yaml.Unmarshal(data, &chart)
		require.NoError(t, err)

		// Validate required fields
		assert.Equal(t, "v2", chart["apiVersion"])
		assert.Equal(t, "go-auth-system", chart["name"])
		assert.Equal(t, "application", chart["type"])
		assert.NotEmpty(t, chart["version"])
		assert.NotEmpty(t, chart["appVersion"])
		assert.NotEmpty(t, chart["description"])
	})

	t.Run("ValidateDefaultValues", func(t *testing.T) {
		filePath := filepath.Join(chartDir, "values.yaml")
		data, err := os.ReadFile(filePath)
		require.NoError(t, err)

		var values map[string]interface{}
		err = yaml.Unmarshal(data, &values)
		require.NoError(t, err)

		// Validate key configuration sections exist
		assert.Contains(t, values, "image")
		assert.Contains(t, values, "app")
		assert.Contains(t, values, "service")
		assert.Contains(t, values, "ingress")
		assert.Contains(t, values, "healthChecks")
		assert.Contains(t, values, "config")
		assert.Contains(t, values, "secrets")
		assert.Contains(t, values, "postgresql")
		assert.Contains(t, values, "redis")
		assert.Contains(t, values, "monitoring")

		// Validate app configuration
		app := values["app"].(map[string]interface{})
		assert.Equal(t, float64(3), app["replicaCount"])
		assert.Contains(t, app, "resources")
		assert.Contains(t, app, "securityContext")
	})
}

// TestHelmTemplate tests Helm template rendering
func TestHelmTemplate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Helm template test in short mode")
	}

	// This test would use helm template command to render templates
	// and validate the output
	t.Run("RenderTemplates", func(t *testing.T) {
		// TODO: Implement helm template testing
		// This would involve:
		// 1. Running `helm template` command
		// 2. Parsing the output
		// 3. Validating the rendered manifests
		t.Skip("Helm template test not yet implemented")
	})
}
