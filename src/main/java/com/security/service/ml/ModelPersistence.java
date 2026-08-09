package com.security.service.ml;

import com.security.config.AppConfig;
import com.security.utils.Logger;
import weka.classifiers.Classifier;
import weka.core.SerializationHelper;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * ModelPersistence - Saves and loads trained ML models.
 * Saves models to disk so they don't need retraining on every run.
 * Industry practice: train once, predict many times.
 */
public class ModelPersistence {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "ModelPersistence";

    private final AppConfig config = AppConfig.getInstance();

    // ── Save Model ───────────────────────────────

    /**
     * Saves a trained classifier to a .model file.
     *
     * @param classifier  the trained Weka classifier
     * @param filePath    where to save (e.g. "models/rf_model.model")
     * @return true if saved successfully
     */
    public boolean saveModel(Classifier classifier, String filePath) {
        try {
            // Create directory if needed
            String dir = filePath.substring(
                    0, filePath.lastIndexOf("/"));
            Files.createDirectories(Paths.get(dir));

            SerializationHelper.write(filePath, classifier);

            log.info(SOURCE, "Model saved to: " + filePath);
            return true;

        } catch (Exception e) {
            log.error(SOURCE,
                    "Failed to save model: " + e.getMessage());
            return false;
        }
    }

    /**
     * Saves the Random Forest model to the configured path.
     * This is the primary model used for predictions.
     */
    public boolean savePrimaryModel(Classifier classifier) {
        return saveModel(classifier, config.getModelPath());
    }

    /**
     * Saves the Decision Tree model to a secondary path.
     */
    public boolean saveDecisionTree(Classifier classifier) {
        String path = config.getModelPath()
                .replace("threat_model", "decision_tree");
        return saveModel(classifier, path);
    }

    // ── Load Model ───────────────────────────────

    /**
     * Loads a trained classifier from a .model file.
     *
     * @param filePath  path to the .model file
     * @return loaded classifier, or null if not found
     */
    public Classifier loadModel(String filePath) {
        try {
            if (!Files.exists(Paths.get(filePath))) {
                log.warn(SOURCE,
                        "Model file not found: " + filePath);
                return null;
            }

            Classifier classifier = (Classifier)
                    SerializationHelper.read(filePath);

            log.info(SOURCE,
                    "Model loaded from: " + filePath);
            return classifier;

        } catch (Exception e) {
            log.error(SOURCE,
                    "Failed to load model: " + e.getMessage());
            return null;
        }
    }

    /**
     * Loads the primary (Random Forest) model.
     * Returns null if not yet trained.
     */
    public Classifier loadPrimaryModel() {
        return loadModel(config.getModelPath());
    }

    // ── Check Model Exists ───────────────────────

    /**
     * Checks if a saved model file exists on disk.
     * Used at startup to decide: load or retrain.
     */
    public boolean modelExists() {
        return Files.exists(Paths.get(config.getModelPath()));
    }

    /**
     * Deletes the saved model file.
     * Call this to force retraining on next run.
     */
    public boolean deleteModel() {
        try {
            Files.deleteIfExists(Paths.get(config.getModelPath()));
            log.info(SOURCE, "Model file deleted.");
            return true;
        } catch (Exception e) {
            log.error(SOURCE,
                    "Failed to delete model: " + e.getMessage());
            return false;
        }
    }
}
