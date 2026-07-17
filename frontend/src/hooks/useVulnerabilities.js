import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getVulnerabilities, updateVulnerabilityStatus, regenerateFix } from '../api/vulnerabilities';

export const useVulnerabilities = ({ projectId, severity, type, search }) => {
  const vulnerabilitiesQuery = useQuery({
    queryKey: ['vulnerabilities', { projectId, severity, type, search }],
    queryFn: () => getVulnerabilities({ projectId, severity, type, search }),
    enabled: !!projectId,
  });

  return {
    vulnerabilities: vulnerabilitiesQuery.data || [],
    isLoading: vulnerabilitiesQuery.isLoading,
    error: vulnerabilitiesQuery.error,
    refetch: vulnerabilitiesQuery.refetch,
  };
};

export const useVulnerabilityActions = (projectId) => {
  const queryClient = useQueryClient();

  const updateStatusMutation = useMutation({
    mutationFn: ({ vulnId, fixed }) => updateVulnerabilityStatus(vulnId, fixed),
    onSuccess: () => {
      // Invalidate current vulnerabilities and projects to update dashboards
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      queryClient.invalidateQueries({ queryKey: ['scans', projectId] });
    },
  });

  const regenerateFixMutation = useMutation({
    mutationFn: (vulnId) => regenerateFix(vulnId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
    },
  });

  return {
    updateStatus: updateStatusMutation.mutateAsync,
    isUpdating: updateStatusMutation.isPending,
    regenerateFix: regenerateFixMutation.mutateAsync,
    isRegenerating: regenerateFixMutation.isPending,
  };
};
