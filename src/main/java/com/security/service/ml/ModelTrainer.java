package com.security.service.ml;

import com.security.config.AppConfig;
import com.security.utils.Logger;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;
import weka.core.Instances;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * ModelTrainer - Trains ML models using Weka.
 * Trains two models:
 *   1. J48 Decision Tree  - Fast, explainable
 *   2. Random Forest      - More accurate, robust
 * Both models are trained on training_data.arff
 */
public class ModelTrainer {

    private static final Logger log = Logger.getInstance();
    private static final String SOURCE = "ModelTrainer";

    private final AppConfig config = AppConfig.getInstance();
    private final DataPreprocessor preprocessor = new DataPreprocessor();

    // Trained models
    private J48          decisionTree;
    private RandomForest randomForest;
    private Instances    trainingData;

    // ── Main Training Method ──────────────────────

    /**
     * Full training pipeline:
     * 1. Load ARFF data
     * 2. Train J48 Decision Tree
     * 3. Train Random Forest
     * 4. Create model output directory
     */
    public boolean trainAll() {
        log.info(SOURCE, "Starting ML model training...");

        // Step 1: Load training data
        trainingData = preprocessor.loadArffFile(
                config.getTrainingDataPath());

        if (trainingData == null) {
            log.error(SOURCE, "Training aborted: no data loaded.");
            return false;
        }

        preprocessor.printDataSummary(trainingData);

        // Step 2: Create output directory
        createModelDirectory();

        // Step 3: Train both models
        boolean tree   = trainDecisionTree();
        boolean forest = trainRandomForest();

        if (tree && forest) {
            log.info(SOURCE,
                    "All models trained successfully!");
            return true;
        }
        log.error(SOURCE, "One or more models failed to train.");
        return false;
    }

    // ── Train J48 Decision Tree ───────────────────

    /**
     * Trains a J48 Decision Tree classifier.
     * J48 is interpretable - you can see the rules it learns.
     */
    private boolean trainDecisionTree() {
        try {
            log.info(SOURCE, "Training J48 Decision Tree...");

            decisionTree = new J48();
            // Use pruning for better generalization
            decisionTree.setUnpruned(false);
            decisionTree.buildClassifier(trainingData);

            log.info(SOURCE,
                    "J48 Decision Tree trained successfully.");
            return true;

        } catch (Exception e) {
            log.error(SOURCE,
                    "J48 training failed: " + e.getMessage());
            return false;
        }
    }

    // ── Train Random Forest ───────────────────────

    /**
     * Trains a Random Forest classifier.
     * Random Forest is more accurate than a single tree.
     * Uses 100 trees for robust predictions.
     */
    private boolean trainRandomForest() {
        try {
            log.info(SOURCE, "Training Random Forest...");

            randomForest = new RandomForest();
            // 100 trees for better accuracy
            randomForest.setNumIterations(100);
            randomForest.buildClassifier(trainingData);

            log.info(SOURCE,
                    "Random Forest trained successfully.");
            return true;

        } catch (Exception e) {
            log.error(SOURCE,
                    "Random Forest training failed: " + e.getMessage());
            return false;
        }
    }

    // ── Create Model Directory ────────────────────

    /** Creates the models/ directory if it doesn't exist. */
    private void createModelDirectory() {
        try {
            String modelPath = config.getModelPath();
            String dir = modelPath.substring(
                    0, modelPath.lastIndexOf("/"));
            Files.createDirectories(Paths.get(dir));
            log.info(SOURCE, "Model directory ready: " + dir);
        } catch (Exception e) {
            log.warn(SOURCE,
                    "Could not create model directory: "
                            + e.getMessage());
        }
    }

    // ── Getters ──────────────────────────────────

    /** Returns the trained J48 Decision Tree. */
    public J48 getDecisionTree() {
        return decisionTree;
    }

    /** Returns the trained Random Forest. */
    public RandomForest getRandomForest() {
        return randomForest;
    }

    /** Returns the training dataset. */
    public Instances getTrainingData() {
        return trainingData;
    }
}