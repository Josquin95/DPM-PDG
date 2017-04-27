install.packages("caTools")
install.packages("RWeka")

library(caTools)

library(RWeka)
################# J48 #################
data <- read.csv("try.csv")
spl = sample.split(data$someAttribute, SplitRatio = 0.7)

dataTrain = subset(data, spl==TRUE)
dataTest = subset(data, spl==FALSE)

resultJ48 <- J48(as.factor(classAttribute)~., dataTrain) 
dataTest.pred <- predict(resultJ48, newdata = dataTest)
table(dataTest$classAttribute, dataTest.pred)


################# NaiveBayes #################

#http://www.learnbymarketing.com/tutorials/naive-bayes-in-r/

install.packages("e1071")

library(e1071) 

## Categorical data only:
data(HouseVotes84)
model <- naiveBayes(Class ~ ., data = HouseVotes84)
predict(model, HouseVotes84[1:10,-1])
predict(model, HouseVotes84[1:10,-1], type = "raw")

pred <- predict(model, HouseVotes84[,-1])
table(pred, HouseVotes84$Class)

## Example of using a contingency table:
data(Titanic)
m <- naiveBayes(Survived ~ ., data = Titanic)
m
predict(m, as.data.frame(Titanic)[,1:3])

## Example with metric predictors:
data(iris)
m <- naiveBayes(Species ~ ., data = iris)
## alternatively:
m <- naiveBayes(iris[,-5], iris[,5])
m
table(predict(m, iris[,-5]), iris[,5])

