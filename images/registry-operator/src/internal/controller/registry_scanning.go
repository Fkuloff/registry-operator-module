package controller

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"registry-operator/apis/registry.kubecontroller.io/v1alpha1"
	"registry-operator/internal/registry"
)

// scanRegistry scans the registry for image tags and details.
func (r *RegistryReconciler) scanRegistry(ctx context.Context, reg *v1alpha1.Registry) ([]v1alpha1.ImageInfo, error) {
	logger := log.FromContext(ctx)

	username, password, err := r.getCredentials(ctx, reg)
	if err != nil {
		return nil, fmt.Errorf("get credentials: %w", err)
	}

	scanCfg := r.getScanConfig(reg)

	regClient := registry.NewClient(
		reg.Spec.URL,
		username,
		password,
		reg.Spec.InsecureSkipVerify,
		registry.WithTimeout(scanCfg.timeout),
	)

	var tags []string
	err = r.withRetry(scanCfg, func() error {
		var retryErr error
		tags, retryErr = regClient.ListTags(ctx, reg.Spec.Repository)
		return retryErr
	})
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}

	tags, err = filterTags(tags, reg.Spec.TagFilter)
	if err != nil {
		return nil, fmt.Errorf("filter tags: %w", err)
	}

	return r.fetchImageDetails(ctx, logger, regClient, reg.Spec.Repository, tags, scanCfg)
}

// filterTags filters and sorts tags based on TagFilter configuration.
func filterTags(tags []string, filter *v1alpha1.TagFilter) ([]string, error) {
	if filter == nil {
		return tags, nil
	}

	var (
		includeRegex *regexp.Regexp
		excludeRegex *regexp.Regexp
		err          error
	)

	if filter.Include != "" {
		includeRegex, err = regexp.Compile(filter.Include)
		if err != nil {
			return nil, fmt.Errorf("compile include pattern %q: %w", filter.Include, err)
		}
	}

	if filter.Exclude != "" {
		excludeRegex, err = regexp.Compile(filter.Exclude)
		if err != nil {
			return nil, fmt.Errorf("compile exclude pattern %q: %w", filter.Exclude, err)
		}
	}

	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		if includeRegex != nil && !includeRegex.MatchString(tag) {
			continue
		}
		if excludeRegex != nil && excludeRegex.MatchString(tag) {
			continue
		}
		result = append(result, tag)
	}

	switch filter.SortBy {
	case "newest":
		sort.Sort(sort.Reverse(sort.StringSlice(result)))
	case "oldest", "alphabetical", "":
		sort.Strings(result)
	}

	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}

	return result, nil
}

// fetchImageDetails fetches details for all tags using worker pool pattern.
func (r *RegistryReconciler) fetchImageDetails(
	ctx context.Context,
	logger logr.Logger,
	regClient *registry.Client,
	repository string,
	tags []string,
	cfg resolvedScanConfig,
) ([]v1alpha1.ImageInfo, error) {
	if len(tags) == 0 {
		return nil, nil
	}

	type job struct {
		index int
		tag   string
	}

	results := make([]v1alpha1.ImageInfo, len(tags))
	jobs := make(chan job, len(tags))

	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					results[j.index] = v1alpha1.ImageInfo{Tag: j.tag}
					continue
				}
				results[j.index] = r.fetchSingleImageDetails(ctx, logger, regClient, repository, j.tag, cfg)
			}
		}()
	}

	for i, tag := range tags {
		select {
		case jobs <- job{index: i, tag: tag}:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		}
	}
	close(jobs)

	wg.Wait()
	return results, nil
}

// fetchSingleImageDetails fetches details for a single image tag with retry logic.
func (r *RegistryReconciler) fetchSingleImageDetails(
	ctx context.Context,
	logger logr.Logger,
	regClient *registry.Client,
	repository, tag string,
	cfg resolvedScanConfig,
) v1alpha1.ImageInfo {
	info := v1alpha1.ImageInfo{Tag: tag}

	err := r.withRetry(cfg, func() error {
		details, err := regClient.GetImageDetails(ctx, repository, tag)
		if err != nil {
			return err
		}
		info.Digest = details.Digest
		info.Size = details.Size
		return nil
	})
	if err != nil {
		logger.V(1).Info("get image details: failed", "tag", tag, "error", err)
	}

	return info
}
